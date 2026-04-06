// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events/conn"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/filter"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/goprobe"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/ssl"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -target $(go env GOARCH) -cc clang apiObserver ../BPF/api_observer.bpf.c"

// APIObserver captures and processes network events via eBPF.
type APIObserver struct {
	Logger fd.Feeder

	nodeName string

	// BPF compiled objects and attached probe links.
	objs  apiObserverObjects
	links []io.Closer

	// Ring buffer: BPF emits samples here; we drain into EventsChannel.
	Events        *ringbuf.Reader
	EventsChannel chan []byte

	// Go HTTP/2 header events ring buffer.
	goHeaderEvents  *ringbuf.Reader
	goHeaderChannel chan []byte

	// Pipeline components.
	filterer    *filter.Filterer
	correlator  events.Correlator
	connManager *conn.ConnectionManager

	// Event buffer: batches events and flushes periodically.
	eventBuf   []*pb.APIEvent
	eventBufMu sync.Mutex

	// Go uprobe path hints keyed by PID.
	// Used to recover missing HTTP/2 :path in mid-stream HPACK cases.
	goPathHints   map[uint32]goPathHint
	goPathHintsMu sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type goPathHint struct {
	path      string
	updatedAt time.Time
}

func NewAPIObserver(node tp.Node, pinpath string, logger fd.Feeder) (*APIObserver, error) {
	ao := &APIObserver{
		Logger:      logger,
		nodeName:    node.NodeName,
		goPathHints: make(map[uint32]goPathHint),
	}
	ao.ctx, ao.cancel = context.WithCancel(context.Background())

	var err error
	if err = rlimit.RemoveMemlock(); err != nil {
		ao.Logger.Errf("Error removing rlimit: %v", err)
		return nil, err
	}

	// Clean stale pinned maps that may have incompatible sizes from
	// a previous run (e.g., go_offsets_map grew from 7→17 entries).
	cleanStalePins(pinpath, ao.Logger)

	if err = loadApiObserverObjects(&ao.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinpath},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			ao.Logger.Errf("BPF verifier error: %v", ve)
		}
		ao.Logger.Errf("Error loading API Observer BPF objects: %v", err)
		return nil, err
	}
	ao.Logger.Print("API Observer eBPF objects loaded successfully")

	if err = ao.attachTracepoint(); err != nil {
		ao.Logger.Warnf("Failed to attach tracepoint (connection tracking degraded): %v", err)
	}

	if err = ao.attachKprobes(); err != nil {
		ao.Logger.Warnf("Failed to initialize system api observer: %s", err.Error())
		return nil, err
	}

	ao.Events, err = ringbuf.NewReader(ao.objs.ApiobserverEvents)
	if err != nil {
		ao.Logger.Errf("Error creating ring buffer reader: %v", err)
		return nil, err
	}

	ao.EventsChannel = make(chan []byte, 4096)
	ao.Logger.Print("Ring buffer reader created")

	ao.filterer = filter.NewFilterer()
	cor := events.NewCorrelator(30 * time.Second)
	ao.correlator = cor
	ao.connManager = conn.NewManager(cor, conn.DefaultConfig())
	ao.Logger.Print("API Observer processing components initialized")

	// Start the Go HTTP/2 header events ring buffer.
	ao.goHeaderEvents, err = ringbuf.NewReader(ao.objs.GoHttp2Events)
	if err != nil {
		ao.Logger.Warnf("Go HTTP/2 header events ring buffer not available (uprobe headers disabled): %v", err)
	} else {
		ao.goHeaderChannel = make(chan []byte, 2048)
		ao.Logger.Print("Go HTTP/2 header events ring buffer created")
	}

	go ao.TraceEvents()
	go ao.flushLoop()

	// Start background Go HTTP/2 uprobe scanner.
	go ao.attachGoHTTP2Uprobes()

	// Start background SSL library scanner (HTTPS capture).
	go ao.attachSSLUprobes()

	return ao, nil
}

func (ao *APIObserver) attachTracepoint() error {
	tpLink, err := link.Tracepoint("sock", "inet_sock_set_state",
		ao.objs.TracepointInetSockSetState, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	ao.links = append(ao.links, tpLink)
	ao.Logger.Print("Tracepoint inet_sock_set_state attached")
	return nil
}

func (ao *APIObserver) attachKprobes() error {
	pfx := syscallPrefix()
	// Egress: write + writev + sendto + sendmsg
	ao.attachSyscallKprobe(pfx+"write", "ksys_write", ao.objs.KprobeSysWrite)
	ao.attachSyscallKprobe(pfx+"writev", "sys_writev", ao.objs.KprobeSysWritev)
	ao.attachSyscallKprobe(pfx+"sendto", "sys_sendto", ao.objs.KprobeSysSendto)
	ao.attachSyscallKprobe(pfx+"sendmsg", "sys_sendmsg", ao.objs.KprobeSysSendmsg)

	// Ingress: read + readv + recvfrom + recvmsg (entry + return)
	ao.attachSyscallKprobe(pfx+"read", "ksys_read", ao.objs.KprobeSysRead)
	ao.attachSyscallKretprobe(pfx+"read", "ksys_read", ao.objs.KretprobeSysRead)
	ao.attachSyscallKprobe(pfx+"readv", "sys_readv", ao.objs.KprobeSysReadv)
	ao.attachSyscallKretprobe(pfx+"readv", "sys_readv", ao.objs.KretprobeSysReadv)
	ao.attachSyscallKprobe(pfx+"recvfrom", "sys_recvfrom", ao.objs.KprobeSysRecvfrom)
	ao.attachSyscallKretprobe(pfx+"recvfrom", "sys_recvfrom", ao.objs.KretprobeSysRecvfrom)
	ao.attachSyscallKprobe(pfx+"recvmsg", "sys_recvmsg", ao.objs.KprobeSysRecvmsg)
	ao.attachSyscallKretprobe(pfx+"recvmsg", "sys_recvmsg", ao.objs.KretprobeSysRecvmsg)

	// FD lifecycle
	ao.attachSyscallKprobe(pfx+"connect", "sys_connect", ao.objs.KprobeSysConnect)
	ao.attachSyscallKretprobe(pfx+"connect", "sys_connect", ao.objs.KretprobeSysConnect)
	ao.attachSyscallKretprobe(pfx+"accept", "sys_accept", ao.objs.KretprobeSysAccept)
	ao.attachSyscallKretprobe(pfx+"accept4", "sys_accept4", ao.objs.KretprobeSysAccept4)
	ao.attachSyscallKprobe(pfx+"close", "sys_close", ao.objs.KprobeSysClose)
	return nil
}

// syscallPrefix returns the architecture-specific kprobe symbol prefix.
func syscallPrefix() string {
	switch runtime.GOARCH {
	case "arm64":
		return "__arm64_sys_"
	default:
		return "__x64_sys_"
	}
}

func (ao *APIObserver) attachSyscallKprobe(primary, fallback string, prog *ebpf.Program) {
	kp, err := link.Kprobe(primary, prog, nil)
	if err != nil {
		kp, err = link.Kprobe(fallback, prog, nil)
		if err != nil {
			ao.Logger.Warnf("Failed to attach kprobe %s (FD tracking degraded): %v", fallback, err)
			return
		}
	}
	ao.links = append(ao.links, kp)
	ao.Logger.Printf("Kprobe %s attached (FD lifecycle)", fallback)
}

func (ao *APIObserver) attachSyscallKretprobe(primary, fallback string, prog *ebpf.Program) {
	kp, err := link.Kretprobe(primary, prog, nil)
	if err != nil {
		kp, err = link.Kretprobe(fallback, prog, nil)
		if err != nil {
			ao.Logger.Warnf("Failed to attach kretprobe %s (FD tracking degraded): %v", fallback, err)
			return
		}
	}
	ao.links = append(ao.links, kp)
	ao.Logger.Printf("Kretprobe %s attached (FD lifecycle)", fallback)
}

// Event loop
func (ao *APIObserver) TraceEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.Events == nil {
		ao.Logger.Err("Ring buffer reader is nil — exiting TraceEvents")
		return
	}
	ao.Logger.Print("Starting TraceEvents from API Observer")

	go func() {
		for {
			record, err := ao.Events.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Ringbuf read error: %v", err)
				continue
			}
			select {
			case ao.EventsChannel <- record.RawSample:
			case <-ao.ctx.Done():
				return
			default:
				// Drop on overload rather than blocking the BPF reader.
				slog.Debug("Dropping API Log due to load")
			}
		}
	}()

	for {
		select {
		case <-ao.ctx.Done():
			ao.Logger.Print("API Observer context cancelled — stopping")
			return
		case dataRaw := <-ao.EventsChannel:
			ev, err := events.ParseDataEvent(dataRaw)
			if err != nil {
				ao.Logger.Debugf("ParseDataEvent error: %v", err)
				continue
			}
			ao.processEvent(*ev)
		}
	}
}

// drainGoHeaderEvents reads from the Go HTTP/2 header events ring buffer
// and processes completed header blocks into the correlator.
func (ao *APIObserver) drainGoHeaderEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.goHeaderEvents == nil {
		return
	}

	ao.Logger.Print("Starting Go HTTP/2 header events reader")

	// Ring buffer reader goroutine.
	go func() {
		for {
			record, err := ao.goHeaderEvents.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				ao.Logger.Warnf("Go header ringbuf read error: %v", err)
				continue
			}
			select {
			case ao.goHeaderChannel <- record.RawSample:
			case <-ao.ctx.Done():
				return
			default:
				slog.Debug("Dropping Go header event due to load")
			}
		}
	}()

	// Processing loop.
	for {
		select {
		case <-ao.ctx.Done():
			return
		case raw := <-ao.goHeaderChannel:
			ev, err := events.ParseGoGRPCRequestEvent(raw)
			if err != nil {
				ao.Logger.Debugf("ParseGoGRPCRequestEvent error: %v", err)
				continue
			}
			ao.processGoGRPCEvent(ev)
		}
	}
}

// processGoGRPCEvent handles a complete gRPC request event from the BPF uprobe.
// Each event contains a full path and latency — no accumulation needed.
func (ao *APIObserver) processGoGRPCEvent(ev *events.GoGRPCRequestEvent) {
	if ev.Path == "" {
		slog.Debug("Go uprobe: ignoring event with empty path",
			"pid", ev.PID, "type", ev.EventType)
		return
	}

	direction := "server"
	if ev.EventType == events.GoGRPCEventClientRequest {
		direction = "client"
	}

	ao.Logger.Printf("Go uprobe: gRPC %s event pid=%d path=%s status=%d latency=%dns",
		direction, ev.PID, ev.Path, ev.Status, ev.LatencyNs())

	// Keep a short-lived PID->path hint so the socket pipeline can recover
	// missing HTTP/2 paths when tracing starts mid-connection.
	ao.setGoPathHint(ev.PID, ev.Path)

	grpcService, grpcMethod := splitGRPCPath(ev.Path)
	grpcStatus := int32(ev.Status)
	httpStatus := int32(200)
	if grpcStatus != 0 {
		httpStatus = 500
	}
	latencyMs := uint32(ev.LatencyNs() / 1_000_000)
	if latencyMs == 0 && ev.LatencyNs() > 0 {
		latencyMs = 1
	}

	apiEvent := pb.APIEvent{
		Metadata: &pb.Metadata{
			Timestamp:    uint64(time.Now().UnixNano()),
			NodeName:     ao.nodeName,
			ReceiverName: "KubeArmor",
		},
		Source: &pb.Workload{
			Name: fmt.Sprintf("pid-%d", ev.PID),
		},
		Destination: &pb.Workload{
			Name: "unknown",
		},
		Request: &pb.Request{
			Method: "POST",
			Path:   ev.Path,
			Headers: map[string]string{
				":method":      "POST",
				":path":        ev.Path,
				":scheme":      "gRPC",
				":authority":   "unknown",
				"content-type": "application/grpc",
			},
			GrpcService: grpcService,
			GrpcMethod:  grpcMethod,
			ContentType: "application/grpc",
		},
		Response: &pb.Response{
			StatusCode: httpStatus,
			Headers: map[string]string{
				":status":     fmt.Sprintf("%d", httpStatus),
				"grpc-status": fmt.Sprintf("%d", ev.Status),
			},
			GrpcStatusCode:    grpcStatus,
			GrpcStatusMessage: grpcStatusMessage(ev.Status),
		},
		Protocol:  "gRPC",
		LatencyMs: latencyMs,
	}

	ao.bufferEvent(&apiEvent)

	// Inject into correlator so future kprobe events for this PID
	// can match the path.
	ao.correlator.InjectGoGRPCEvent(ev.PID, ev.Path, ev.Status, ev.StartNs, ev.EndNs)
}

func splitGRPCPath(path string) (service, method string) {
	p := strings.TrimPrefix(path, "/")
	parts := strings.SplitN(p, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

func grpcStatusMessage(status uint16) string {
	switch status {
	case 0:
		return "OK"
	case 1:
		return "CANCELLED"
	case 2:
		return "UNKNOWN"
	case 3:
		return "INVALID_ARGUMENT"
	case 4:
		return "DEADLINE_EXCEEDED"
	case 5:
		return "NOT_FOUND"
	case 6:
		return "ALREADY_EXISTS"
	case 7:
		return "PERMISSION_DENIED"
	case 8:
		return "RESOURCE_EXHAUSTED"
	case 9:
		return "FAILED_PRECONDITION"
	case 10:
		return "ABORTED"
	case 11:
		return "OUT_OF_RANGE"
	case 12:
		return "UNIMPLEMENTED"
	case 13:
		return "INTERNAL"
	case 14:
		return "UNAVAILABLE"
	case 15:
		return "DATA_LOSS"
	case 16:
		return "UNAUTHENTICATED"
	default:
		return "UNKNOWN"
	}
}

func (ao *APIObserver) processEvent(ev events.DataEvent) {
	traces := ao.connManager.Route(&ev)
	for _, trace := range traces {
		ao.applyGoPathHint(trace, ev.PID)
		ao.enrichAndEmit(trace, &ev)
	}
}

func (ao *APIObserver) setGoPathHint(pid uint32, path string) {
	if pid == 0 || path == "" {
		return
	}
	ao.goPathHintsMu.Lock()
	ao.goPathHints[pid] = goPathHint{
		path:      path,
		updatedAt: time.Now(),
	}
	ao.goPathHintsMu.Unlock()
}

func (ao *APIObserver) getGoPathHint(pid uint32, maxAge time.Duration) (string, bool) {
	if pid == 0 {
		return "", false
	}

	ao.goPathHintsMu.RLock()
	hint, ok := ao.goPathHints[pid]
	ao.goPathHintsMu.RUnlock()
	if !ok {
		return "", false
	}

	if time.Since(hint.updatedAt) > maxAge {
		ao.goPathHintsMu.Lock()
		delete(ao.goPathHints, pid)
		ao.goPathHintsMu.Unlock()
		return "", false
	}
	return hint.path, true
}

func (ao *APIObserver) applyGoPathHint(trace *events.CorrelatedTrace, pid uint32) {
	if trace == nil || trace.URL != "" {
		return
	}
	path, ok := ao.getGoPathHint(pid, 15*time.Second)
	if !ok || path == "" {
		return
	}
	trace.URL = path
	if trace.Method == "" {
		trace.Method = "POST"
	}
}

// Emit path

func sanitizeUTF8(s string) string {
	return strings.ToValidUTF8(s, "")
}

// sanitizeBody returns a clean body string. If the body contains non-printable
// bytes (raw protobuf that wasn't decoded), base64-encode it with a prefix
// so downstream consumers know it's encoded.
func sanitizeBody(s string) string {
	if s == "" {
		return ""
	}
	// Check if body has non-printable characters (control chars excluding
	// tab/newline/carriage-return).
	for _, b := range []byte(s) {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return "[base64]" + base64.StdEncoding.EncodeToString([]byte(s))
		}
	}
	return sanitizeUTF8(s)
}

func sanitizeHeaders(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	res := make(map[string]string, len(m))
	for k, v := range m {
		res[sanitizeUTF8(k)] = sanitizeUTF8(v)
	}
	return res
}

func (ao *APIObserver) enrichAndEmit(trace *events.CorrelatedTrace, ev *events.DataEvent) {
	// Non-routable IP filter (loopback, multicast, broadcast).
	if ao.filterer.IsLoopbackTraffic(ev.SrcIPString(), ev.DstIPString()) {
		return
	}

	// Request-level filters.
	ua := trace.RequestHeaders["user-agent"]
	if !ao.filterer.ShouldTraceRequest(trace.URL, ua) {
		return
	}
	if ao.filterer.IsHealthProbe(trace.URL, ua, trace.ResponseBody) {
		return
	}

	srcName, srcNS := ao.resolveWorkload(ev.SrcIPString())
	dstName, dstNS := ao.resolveWorkload(ev.DstIPString())

	if !ao.filterer.ShouldTraceConnection(srcName, dstName, srcNS, dstNS) {
		return
	}
	// Deduplication: both client and server perspectives of the same call
	// produce events within microseconds. IsDuplicate uses sorted IPs so
	// both perspectives hash to the same key.
	if ao.filterer.IsDuplicate(ev.SrcIPString(), ev.DstIPString(),
		int32(ev.SrcPort), int32(ev.DstPort),
		trace.Method, trace.URL, trace.Status) {
		return
	}

	var statusCode int32
	if n, err := fmt.Sscanf(trace.Status, "%d", &statusCode); n == 0 || err != nil {
		statusCode = 0
	}

	// Build pb.APIEvent.
	latencyMs := uint32(trace.DurationNs / 1_000_000)

	// Resolve :authority for pseudo-headers.
	authority := trace.RequestHeaders["host"]
	if authority == "" {
		authority = trace.RequestHeaders[":authority"]
	}
	if authority == "" {
		authority = dstName
	}

	// Ensure method and path are always populated.
	method := sanitizeUTF8(trace.Method)
	if method == "" {
		method = "UNKNOWN"
	}
	path := sanitizeUTF8(trace.URL)
	if path == "" {
		path = "*"
	}

	// Build request headers with HTTP/2 pseudo-headers.
	reqHeaders := sanitizeHeaders(trace.RequestHeaders)
	if reqHeaders == nil {
		reqHeaders = make(map[string]string)
	}
	reqHeaders[":method"] = method
	reqHeaders[":path"] = path
	reqHeaders[":scheme"] = "http"

	if trace.IsEncrypted {
		reqHeaders[":scheme"] = "https"
	}
	reqHeaders[":authority"] = authority

	isGRPC := ev.ProtocolString() == "gRPC" || strings.HasPrefix(trace.ContentType, "application/grpc") || trace.ResponseHeaders["grpc-status"] != "" || trace.GRPCStatus != 0

	if isGRPC {
		reqHeaders[":scheme"] = "gRPC"
		if trace.GRPCService != "" {
			reqHeaders[":authority"] = trace.GRPCService
		}
	}

	// Build response headers with :status pseudo-header.
	respHeaders := sanitizeHeaders(trace.ResponseHeaders)
	if respHeaders == nil {
		respHeaders = make(map[string]string)
	}
	respHeaders[":status"] = trace.Status

	apiEvent := pb.APIEvent{
		Metadata: &pb.Metadata{
			Timestamp:    uint64(time.Now().UnixNano()),
			NodeName:     ao.nodeName,
			ReceiverName: "KubeArmor",
		},
		Source: &pb.Workload{
			Name:      srcName,
			Namespace: srcNS,
			Ip:        ev.SrcIPString(),
			Port:      int32(ev.SrcPort),
		},
		Destination: &pb.Workload{
			Name:      dstName,
			Namespace: dstNS,
			Ip:        ev.DstIPString(),
			Port:      int32(ev.DstPort),
		},
		Request: &pb.Request{
			Method:      method,
			Path:        path,
			Headers:     reqHeaders,
			Body:        sanitizeBody(trace.RequestBody),
			GrpcService: sanitizeUTF8(trace.GRPCService),
			GrpcMethod:  sanitizeUTF8(trace.GRPCMethod),
			ContentType: sanitizeUTF8(trace.ContentType),
		},
		Response: &pb.Response{
			StatusCode:        statusCode,
			Headers:           respHeaders,
			Body:              sanitizeBody(trace.ResponseBody),
			GrpcStatusCode:    trace.GRPCStatus,
			GrpcStatusMessage: sanitizeUTF8(trace.GRPCMessage),
		},
		Protocol:  ev.ProtocolString(),
		LatencyMs: latencyMs,
	}

	// BUG 5 fix: Override protocol to "gRPC" when content-type or response
	// headers indicate gRPC traffic, regardless of BPF-level classification.
	if strings.HasPrefix(trace.ContentType, "application/grpc") ||
		trace.ResponseHeaders["grpc-status"] != "" {
		apiEvent.Protocol = "gRPC"
	}

	// BUG 8 fix: Default grpc-message to "OK" when grpc-status is 0 (success)
	// and grpc-message is empty. Go gRPC servers omit grpc-message on success.
	if apiEvent.Response.GrpcStatusCode == 0 && apiEvent.Response.GrpcStatusMessage == "" {
		if trace.ResponseHeaders["grpc-status"] == "0" || trace.ContentType == "application/grpc" {
			apiEvent.Response.GrpcStatusMessage = "OK"
		}
	}

	// BUG 3 fix: Truncate oversized bodies at the userspace serialization layer.
	if len(apiEvent.Request.Body) > maxAPIBodyBytes {
		apiEvent.Request.Body = apiEvent.Request.Body[:maxAPIBodyBytes] + "... [truncated]"
	}
	if len(apiEvent.Response.Body) > maxAPIBodyBytes {
		apiEvent.Response.Body = apiEvent.Response.Body[:maxAPIBodyBytes] + "... [truncated]"
	}

	// Buffer the event for batched flushing.
	ao.bufferEvent(&apiEvent)
}

// maxAPIBodyBytes caps the request/response body size in emitted APIEvents.
// Bodies exceeding this limit are truncated at the protobuf serialization
// layer to prevent oversized gRPC messages to downstream consumers.
const maxAPIBodyBytes = 16384

const eventBufCap = 500

// bufferEvent appends an event to the buffer and triggers a flush if full.
func (ao *APIObserver) bufferEvent(ev *pb.APIEvent) {
	ao.eventBufMu.Lock()
	ao.eventBuf = append(ao.eventBuf, ev)
	flush := len(ao.eventBuf) >= eventBufCap
	ao.eventBufMu.Unlock()
	if flush {
		ao.flushEvents()
	}
}

// flushEvents drains the buffer and pushes all events to the feeder.
func (ao *APIObserver) flushEvents() {
	ao.eventBufMu.Lock()
	batch := ao.eventBuf
	ao.eventBuf = nil
	ao.eventBufMu.Unlock()

	for _, ev := range batch {
		ao.Logger.PushAPIEvent(*ev)
	}
}

// flushLoop periodically flushes buffered events every 5 seconds.
func (ao *APIObserver) flushLoop() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ao.flushEvents()
		case <-ao.ctx.Done():
			ao.flushEvents() // Final drain.
			return
		}
	}
}

// K8s metadata resolution

func (ao *APIObserver) resolveWorkload(ip string) (name, namespace string) {
	return ip, ""
}

// attachSSLUprobes scans all running processes for loaded SSL libraries
// (OpenSSL, BoringSSL, libpython, libnetty_tcnative, libconscrypt) using
// /proc/<pid>/maps and attaches the appropriate BPF uprobes.
//
// For each discovered library, it chooses the correct FD extraction method:
//   - Nested syscall: for OpenSSL/Python — tracks FD from underlying syscall
//   - Userspace offsets: for BoringSSL/Netty/Conscrypt — walks ssl->rbio->num
//
// Runs as a background goroutine with periodic rescan (10s).
func (ao *APIObserver) attachSSLUprobes() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	// Track probed library paths to avoid re-probing.
	probed := make(map[string]bool)

	// Pre-attach to host-level system libssl.so.* (Pixie-style).
	// This catches ALL processes using the host's OpenSSL, including
	// short-lived ones like curl that exit before the per-PID scan.
	ao.preAttachHostSSL(probed)

	scanAndAttach := func() {
		pids, err := listPIDs()
		if err != nil {
			ao.Logger.Warnf("SSL library scan: failed to list /proc: %v", err)
			return
		}

		for _, pid := range pids {
			select {
			case <-ao.ctx.Done():
				return
			default:
			}
			matches := ssl.DiscoverSSLLibsForPID(pid)
			for _, match := range matches {
				select {
				case <-ao.ctx.Done():
					return
				default:
				}
				// For userspace offset extraction (BoringSSL/Netty/Conscrypt),
				// offsets are keyed by TGID, so each PID must have a map entry
				// even when the library uprobes were already attached earlier.
				if match.FDMethod == ssl.FDMethodUserSpaceOffsets {
					tgid := pid
					if err := ao.objs.SslSymaddrs.Put(tgid, match.Offsets); err != nil {
						ao.Logger.Warnf("SSL: failed to refresh symaddrs for TGID %d: %v", tgid, err)
					}
				}

				if probed[match.HostPath] {
					continue
				}

				ex, err := link.OpenExecutable(match.HostPath)
				if err != nil {
					ao.Logger.Warnf("SSL: failed to open %s: %v", match.HostPath, err)
					continue
				}

				probeCount := 0

				switch match.FDMethod {
				case ssl.FDMethodNestedSyscall:
					// Nested syscall path: use *_syscall_fd variants
					probeCount += ao.attachSSLProbe(ex, "SSL_write", ao.objs.UprobeSslWriteSyscallFd, ao.objs.UretprobeSslWriteSyscallFd, match.HostPath)
					probeCount += ao.attachSSLProbe(ex, "SSL_read", ao.objs.UprobeSslReadSyscallFd, ao.objs.UretprobeSslReadSyscallFd, match.HostPath)
					probeCount += ao.attachSSLProbe(ex, "SSL_write_ex", ao.objs.UprobeSslWriteExSyscallFd, ao.objs.UretprobeSslWriteExSyscallFd, match.HostPath)
					probeCount += ao.attachSSLProbe(ex, "SSL_read_ex", ao.objs.UprobeSslReadExSyscallFd, ao.objs.UretprobeSslReadExSyscallFd, match.HostPath)

				case ssl.FDMethodUserSpaceOffsets:
					// Use standard uprobe/uretprobe (struct offset FD extraction)
					probeCount += ao.attachSSLProbe(ex, "SSL_write", ao.objs.UprobeSslWrite, ao.objs.UretprobeSslWrite, match.HostPath)
					probeCount += ao.attachSSLProbe(ex, "SSL_read", ao.objs.UprobeSslRead, ao.objs.UretprobeSslRead, match.HostPath)
				}

				// Always attach SSL_shutdown for cleanup
				if l, err := ex.Uprobe("SSL_shutdown", ao.objs.UprobeSslShutdown, nil); err == nil {
					ao.links = append(ao.links, l)
					probeCount++
				}

				if probeCount > 0 {
					probed[match.HostPath] = true
					ao.Logger.Printf("Attached %d SSL uprobes [%s] on %s (PID %d, FD: %s)",
						probeCount, match.LibType, match.HostPath, pid, fdMethodStr(match.FDMethod))
				}
			}
		}
	}

	// Initial per-PID scan (catches container-bundled libraries).
	scanAndAttach()

	// Periodic rescan for new processes/libraries (every 10s — Pixie uses ~5-15s).
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ao.ctx.Done():
			return
		case <-ticker.C:
			scanAndAttach()
		}
	}
}

// preAttachHostSSL attaches SSL uprobes to system-wide libssl.so.* paths.
// This is the Pixie-equivalent approach (kOpenSSLUProbes with known paths):
// by probing the host's OpenSSL libraries directly, we capture ALL processes
// that use them — including short-lived clients like curl that exit before
// the per-PID /proc/maps scanner runs.
func (ao *APIObserver) preAttachHostSSL(probed map[string]bool) {
	paths, err := ssl.LibSSLPaths()
	if err != nil {
		ao.Logger.Warnf("SSL pre-attach: no system libssl found: %v", err)
		return
	}

	for _, libPath := range paths {
		if probed[libPath] {
			continue
		}

		ex, err := link.OpenExecutable(libPath)
		if err != nil {
			ao.Logger.Warnf("SSL pre-attach: failed to open %s: %v", libPath, err)
			continue
		}

		probeCount := 0
		// Host OpenSSL always uses nested syscall FD method
		probeCount += ao.attachSSLProbe(ex, "SSL_write", ao.objs.UprobeSslWriteSyscallFd, ao.objs.UretprobeSslWriteSyscallFd, libPath)
		probeCount += ao.attachSSLProbe(ex, "SSL_read", ao.objs.UprobeSslReadSyscallFd, ao.objs.UretprobeSslReadSyscallFd, libPath)
		probeCount += ao.attachSSLProbe(ex, "SSL_write_ex", ao.objs.UprobeSslWriteExSyscallFd, ao.objs.UretprobeSslWriteExSyscallFd, libPath)
		probeCount += ao.attachSSLProbe(ex, "SSL_read_ex", ao.objs.UprobeSslReadExSyscallFd, ao.objs.UretprobeSslReadExSyscallFd, libPath)

		if l, err := ex.Uprobe("SSL_shutdown", ao.objs.UprobeSslShutdown, nil); err == nil {
			ao.links = append(ao.links, l)
			probeCount++
		}

		if probeCount > 0 {
			probed[libPath] = true
			ao.Logger.Printf("SSL pre-attach: attached %d uprobes to host %s", probeCount, libPath)
		}
	}
}

// attachSSLProbe attaches an uprobe+uretprobe pair to a symbol.
// Returns the count of successfully attached probes (0, 1, or 2).
func (ao *APIObserver) attachSSLProbe(
	ex *link.Executable,
	symbol string,
	entry *ebpf.Program,
	ret *ebpf.Program,
	libPath string,
) int {
	count := 0
	if entry != nil {
		if l, err := ex.Uprobe(symbol, entry, nil); err == nil {
			ao.links = append(ao.links, l)
			count++
		} else {
			slog.Warn("SSL uprobe attach failed", "symbol", symbol, "lib", libPath, "err", err)
		}
	}
	if ret != nil {
		if l, err := ex.Uretprobe(symbol, ret, nil); err == nil {
			ao.links = append(ao.links, l)
			count++
		} else {
			slog.Warn("SSL uretprobe attach failed", "symbol", symbol, "lib", libPath, "err", err)
		}
	}
	return count
}

// listPIDs scans /proc for numeric entries (PIDs).
func listPIDs() ([]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []uint32
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func fdMethodStr(m ssl.FDAccessMethod) string {
	switch m {
	case ssl.FDMethodNestedSyscall:
		return "nested_syscall"
	case ssl.FDMethodUserSpaceOffsets:
		return "userspace_offsets"
	default:
		return "unknown"
	}
}

// attachGoHTTP2Uprobes scans for Go HTTP/2 binaries and attaches uprobes.
// Runs as a background goroutine, rescanning periodically for new processes.
func (ao *APIObserver) attachGoHTTP2Uprobes() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	// Map of uprobe short IDs → BPF programs.
	// For Go functions, prefer ret-instruction uprobes over uretprobes (Pixie kReturnInsts).
	probeMap := map[string]*ebpf.Program{
		"server_handleStream":      ao.objs.KaUprobeServerHandleStream,
		"server_handleStream_ret":  nil, // legacy uretprobe (disabled for Go safety)
		"transport_writeStatus":    ao.objs.KaUprobeTransportWriteStatus,
		"ClientConn_Invoke":        ao.objs.KaUprobeClientConnInvoke,
		"ClientConn_Invoke_ret":    nil, // legacy uretprobe (disabled for Go safety)
		"ClientConn_NewStream":     ao.objs.KaUprobeClientConnNewStream,
		"clientStream_RecvMsg_ret": nil, // legacy uretprobe (disabled for Go safety)
	}
	// Go crypto/tls tracing must follow Pixie's approach: attach "return" probes
	// as entry uprobes at every RET instruction (not uretprobes), otherwise the
	// Go runtime can crash with "unexpected return pc".
	tlsEntryMap := map[string]*ebpf.Program{
		"tls_Conn_Write": ao.objs.KaUprobeTlsConnWrite,
		"tls_Conn_Read":  ao.objs.KaUprobeTlsConnRead,
	}
	tlsRetInstMap := map[string]*ebpf.Program{
		"tls_Conn_Write_retinst": ao.objs.KaUprobeTlsConnWriteRetinst,
		"tls_Conn_Read_retinst":  ao.objs.KaUprobeTlsConnReadRetinst,
	}

	grpcRetInstMap := map[string]*ebpf.Program{
		"server_handleStream_retinst":  ao.objs.KaUprobeServerHandleStreamRetinst,
		"ClientConn_Invoke_retinst":    ao.objs.KaUprobeClientConnInvokeRetinst,
		"clientStream_RecvMsg_retinst": ao.objs.KaUprobeClientStreamRecvMsgRetinst,
	}

	// Track attached binaries to avoid re-probing.
	attached := make(map[string]bool)

	scanAndAttach := func() {
		targets, err := goprobe.ScanProc()
		if err != nil {
			ao.Logger.Warnf("Go HTTP/2 binary scan error: %v", err)
			return
		}

		for _, target := range targets {
			select {
			case <-ao.ctx.Done():
				return
			default:
			}
			if attached[target.BinaryPath] {
				// Already probed this binary — just ensure BPF maps are populated.
				ao.populateGoBPFMaps(target)
				continue
			}

			ao.Logger.Printf("Attaching Go HTTP/2 uprobes to %s (PID %d, %d symbols)",
				target.BinaryPath, target.PID, len(target.Symbols))

			// Populate BPF maps with offsets for this PID.
			ao.populateGoBPFMaps(target)

			// Open the executable for uprobe attachment.
			ex, err := link.OpenExecutable(target.BinaryPath)
			if err != nil {
				ao.Logger.Warnf("Failed to open Go binary %s: %v", target.BinaryPath, err)
				continue
			}

			probeCount := 0
			for shortID, addr := range target.Symbols {
				select {
				case <-ao.ctx.Done():
					return
				default:
				}
				// Attach entry uprobe.
				if prog, ok := probeMap[shortID]; ok {
					l, err := ex.Uprobe("", prog, &link.UprobeOptions{
						Address: addr,
					})
					if err != nil {
						ao.Logger.Warnf("Failed to attach uprobe %s at 0x%x on %s: %v",
							shortID, addr, target.BinaryPath, err)
					} else {
						ao.links = append(ao.links, l)
						probeCount++
						ao.Logger.Printf("  uprobe/%s attached at 0x%x", shortID, addr)
					}
				}

			}

			// Attach Go gRPC ret-instruction probes (Pixie kReturnInsts model).
			for retID, retProg := range grpcRetInstMap {
				select {
				case <-ao.ctx.Done():
					return
				default:
				}
				baseID := strings.TrimSuffix(retID, "_retinst")
				cands := goprobe.TargetSymbols[baseID]
				if len(cands) == 0 {
					continue
				}
				retOffs, err := goprobe.FuncRetInstOffsets(target.BinaryPath, cands)
				if err != nil {
					ao.Logger.Warnf("Failed to find RET instructions for %s in %s: %v", baseID, target.BinaryPath, err)
					continue
				}
				for _, ro := range retOffs {
					select {
					case <-ao.ctx.Done():
						return
					default:
					}
					if l, err := ex.Uprobe("", retProg, &link.UprobeOptions{Address: ro}); err == nil {
						ao.links = append(ao.links, l)
						probeCount++
					} else {
						ao.Logger.Warnf("Failed to attach gRPC retinst uprobe %s at 0x%x on %s: %v",
							retID, ro, target.BinaryPath, err)
					}
				}
				ao.Logger.Printf("  uprobe/%s attached at %d RET sites", retID, len(retOffs))
			}

			// Attach Go TLS return-instruction probes (Pixie kReturnInsts model).
			for shortID, entryProg := range tlsEntryMap {
				select {
				case <-ao.ctx.Done():
					return
				default:
				}
				addr, ok := target.Symbols[shortID]
				if !ok {
					continue
				}
				// Entry attach at function start.
				if l, err := ex.Uprobe("", entryProg, &link.UprobeOptions{Address: addr}); err == nil {
					ao.links = append(ao.links, l)
					probeCount++
					ao.Logger.Printf("  uprobe/%s attached at 0x%x", shortID, addr)
				} else {
					ao.Logger.Warnf("Failed to attach TLS entry uprobe %s at 0x%x on %s: %v",
						shortID, addr, target.BinaryPath, err)
					continue
				}

				cands := goprobe.TLSFuncCandidates(shortID)
				retOffs, err := goprobe.FuncRetInstOffsets(target.BinaryPath, cands)
				if err != nil {
					ao.Logger.Warnf("Failed to find RET instructions for %s in %s: %v", shortID, target.BinaryPath, err)
					continue
				}

				retProg := tlsRetInstMap[shortID+"_retinst"]
				if retProg == nil {
					ao.Logger.Warnf("TLS retinst program missing for %s", shortID)
					continue
				}
				for _, ro := range retOffs {
					select {
					case <-ao.ctx.Done():
						return
					default:
					}
					if l, err := ex.Uprobe("", retProg, &link.UprobeOptions{Address: ro}); err == nil {
						ao.links = append(ao.links, l)
						probeCount++
					} else {
						ao.Logger.Warnf("Failed to attach TLS retinst uprobe %s at 0x%x on %s: %v",
							shortID+"_retinst", ro, target.BinaryPath, err)
					}
				}
				ao.Logger.Printf("  uprobe/%s attached at %d RET sites", shortID+"_retinst", len(retOffs))
			}

			if probeCount > 0 {
				attached[target.BinaryPath] = true
				ao.Logger.Printf("Attached %d Go HTTP/2 uprobes on %s",
					probeCount, target.BinaryPath)
			}
		}
	}

	// Initial scan.
	scanAndAttach()

	// Start the Go header events reader after initial scan.
	go ao.drainGoHeaderEvents()

	// Periodic rescan for new Go binaries (every 30 seconds).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ao.ctx.Done():
			return
		case <-ticker.C:
			scanAndAttach()
		}
	}
}

// populateGoBPFMaps writes the offset table into the BPF map for a given target.
func (ao *APIObserver) populateGoBPFMaps(target goprobe.GoUProbeTarget) {
	if target.Inode == 0 {
		ao.Logger.Warnf("populateGoBPFMaps: no inode for %s, skipping", target.BinaryPath)
		return
	}

	ao.Logger.Printf("populateGoBPFMaps: pushing offset table for inode %d (binary %s)",
		target.Inode, target.BinaryPath)

	// Push offset table keyed by inode (matches BPF go_offsets_map).
	// NOTE: GoOffsetsMap field will exist on apiObserverObjects after BPF
	// recompilation with bpf2go. If it doesn't compile, regenerate with:
	//   cd KubeArmor/BPF && make
	if err := ao.objs.GoOffsetsMap.Put(target.Inode, target.OffsetTable); err != nil {
		ao.Logger.Warnf("Failed to update go_offsets_map for inode %d: %v", target.Inode, err)
	}
}

// Lifecycle
func (ao *APIObserver) DestroyAPIObserver() error {
	if ao == nil {
		return nil
	}
	var cleanupErr error
	if ao.cancel != nil {
		ao.cancel()
	}
	if ao.Events != nil {
		if err := ao.Events.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.goHeaderEvents != nil {
		if err := ao.goHeaderEvents.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if err := ao.objs.Close(); err != nil {
		ao.Logger.Err(err.Error())
		cleanupErr = errors.Join(cleanupErr, err)
	}
	for _, l := range ao.links {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil {
			ao.Logger.Err(err.Error())
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if ao.correlator != nil {
		ao.correlator.Stop()
	}
	if ao.connManager != nil {
		ao.connManager.Stop()
	}
	// Wait for all APIObserver goroutines to exit, but log if it takes long.
	waitCh := make(chan struct{})
	go func() {
		ao.wg.Wait()
		close(waitCh)
	}()
	select {
	case <-waitCh:
	case <-time.After(10 * time.Second):
		ao.Logger.Warn("API Observer shutdown taking >5s (waiting for background goroutines to exit)")
		<-waitCh
	}
	return cleanupErr
}

// cleanStalePins removes pinned BPF maps whose key/value sizes no longer
// match the current BPF object. This prevents verifier failures when struct
// layouts change between builds (e.g., go_offsets_map grew from 7→17 entries).
func cleanStalePins(pinpath string, logger fd.Feeder) {
	spec, err := loadApiObserver()
	if err != nil {
		return
	}
	for name, mapSpec := range spec.Maps {
		pinFile := filepath.Join(pinpath, name)
		m, err := ebpf.LoadPinnedMap(pinFile, nil)
		if err != nil {
			continue // Not pinned or can't open — nothing to clean.
		}
		info, err := m.Info()
		m.Close()
		if err != nil {
			continue
		}
		// Compare key and value sizes from the running (pinned) map
		// against what the current BPF object expects.
		if info.KeySize != mapSpec.KeySize || info.ValueSize != mapSpec.ValueSize {
			logger.Printf("Removing stale pinned map %s (pinned key/value %d/%d, expected %d/%d)",
				name, info.KeySize, info.ValueSize, mapSpec.KeySize, mapSpec.ValueSize)
			os.Remove(pinFile)
		}
	}
}
