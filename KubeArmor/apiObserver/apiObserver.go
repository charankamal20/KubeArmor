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
	"strings"
	"sync"
	"syscall"
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
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/grpcc"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/ssl"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang apiObserver ../BPF/api_observer.bpf.c

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
	grpccEvents     *ringbuf.Reader // ring buffer for gRPC-C header events
	grpccChannel    chan []byte

	// Pipeline components.
	filterer    *filter.Filterer
	correlator  events.Correlator
	connManager *conn.ConnectionManager

	// Event buffer: batches events and flushes periodically.
	eventBuf   []*pb.APIEvent
	eventBufMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewAPIObserver(node tp.Node, pinpath string, logger fd.Feeder) (*APIObserver, error) {
	ao := &APIObserver{
		Logger:   logger,
		nodeName: node.NodeName,
	}
	ao.ctx, ao.cancel = context.WithCancel(context.Background())

	var err error
	if err = rlimit.RemoveMemlock(); err != nil {
		ao.Logger.Errf("Error removing rlimit: %v", err)
		return nil, err
	}

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

	ao.grpccEvents, err = ringbuf.NewReader(ao.objs.GrpccEvents)
	if err != nil {
		ao.Logger.Warnf("gRPC-C events ring buffer not available: %v", err)
	} else {
		ao.grpccChannel = make(chan []byte, 1024)
		ao.Logger.Print("gRPC-C events ring buffer created")
	}

	go ao.attachGRPCCUprobes()
	go ao.drainGRPCCEvents()

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
	// Egress: write + writev + sendto + sendmsg
	ao.attachSyscallKprobe("__x64_sys_write", "ksys_write", ao.objs.KprobeSysWrite)
	ao.attachSyscallKprobe("__x64_sys_writev", "sys_writev", ao.objs.KprobeSysWritev)
	ao.attachSyscallKprobe("__x64_sys_sendto", "sys_sendto", ao.objs.KprobeSysSendto)
	ao.attachSyscallKprobe("__x64_sys_sendmsg", "sys_sendmsg", ao.objs.KprobeSysSendmsg)

	// Ingress: read + readv + recvfrom + recvmsg (entry + return)
	ao.attachSyscallKprobe("__x64_sys_read", "ksys_read", ao.objs.KprobeSysRead)
	ao.attachSyscallKretprobe("__x64_sys_read", "ksys_read", ao.objs.KretprobeSysRead)
	ao.attachSyscallKprobe("__x64_sys_readv", "sys_readv", ao.objs.KprobeSysReadv)
	ao.attachSyscallKretprobe("__x64_sys_readv", "sys_readv", ao.objs.KretprobeSysReadv)
	ao.attachSyscallKprobe("__x64_sys_recvfrom", "sys_recvfrom", ao.objs.KprobeSysRecvfrom)
	ao.attachSyscallKretprobe("__x64_sys_recvfrom", "sys_recvfrom", ao.objs.KretprobeSysRecvfrom)
	ao.attachSyscallKprobe("__x64_sys_recvmsg", "sys_recvmsg", ao.objs.KprobeSysRecvmsg)
	ao.attachSyscallKretprobe("__x64_sys_recvmsg", "sys_recvmsg", ao.objs.KretprobeSysRecvmsg)

	// FD lifecycle
	ao.attachSyscallKprobe("__x64_sys_connect", "sys_connect", ao.objs.KprobeSysConnect)
	ao.attachSyscallKretprobe("__x64_sys_connect", "sys_connect", ao.objs.KretprobeSysConnect)
	ao.attachSyscallKretprobe("__x64_sys_accept", "sys_accept", ao.objs.KretprobeSysAccept)
	ao.attachSyscallKretprobe("__x64_sys_accept4", "sys_accept4", ao.objs.KretprobeSysAccept4)
	ao.attachSyscallKprobe("__x64_sys_close", "sys_close", ao.objs.KprobeSysClose)
	return nil
}

func (ao *APIObserver) attachSyscallKprobe(x64name, fallback string, prog *ebpf.Program) {
	kp, err := link.Kprobe(x64name, prog, nil)
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

func (ao *APIObserver) attachSyscallKretprobe(x64name, fallback string, prog *ebpf.Program) {
	kp, err := link.Kretprobe(x64name, prog, nil)
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

	// Inject into correlator so future kprobe events for this PID
	// can match the path.
	ao.correlator.InjectGoGRPCEvent(ev.PID, ev.Path, ev.Status, ev.StartNs, ev.EndNs)
}

func (ao *APIObserver) processEvent(ev events.DataEvent) {
	traces := ao.connManager.Route(&ev)
	for _, trace := range traces {
		ao.enrichAndEmit(trace, &ev)
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

// SSL uprobes -> currently not being called. In Progress
func (ao *APIObserver) attachSSLUprobes() error {
	libPaths, err := ssl.LibSSLPaths()
	if err != nil {
		ao.Logger.Warnf("libssl not found, HTTPS capture disabled: %v", err)
		return nil
	}
	for _, libPath := range libPaths {
		offsets, err := ssl.OffsetsForLib(libPath)
		if err != nil {
			ao.Logger.Warnf("SSL struct offsets unknown for %s: %v", libPath, err)
			continue
		}
		if err := ao.objs.SslSymaddrs.Put(uint32(0), offsets); err != nil {
			return fmt.Errorf("ssl_symaddrs update: %w", err)
		}
		ex, err := link.OpenExecutable(libPath)
		if err != nil {
			return fmt.Errorf("open %s: %w", libPath, err)
		}
		if l, err := attachUprobeWithFallback(ex, "SSL_write", ao.objs.UprobeSslWrite, 0); err == nil {
			ao.links = append(ao.links, l)
			ao.Logger.Printf("uprobe/SSL_write attached (%s)", libPath)
		}
		if lEntry, err := attachUprobeWithFallback(ex, "SSL_read", ao.objs.UprobeSslRead, 0); err == nil {
			ao.links = append(ao.links, lEntry)
			if lRet, err := ex.Uretprobe("SSL_read", ao.objs.UretprobeSslRead, nil); err == nil {
				ao.links = append(ao.links, lRet)
				ao.Logger.Printf("uprobe+uretprobe/SSL_read attached (%s)", libPath)
			}
		}
	}
	return nil
}

// attachGoHTTP2Uprobes scans for Go HTTP/2 binaries and attaches uprobes.
// Runs as a background goroutine, rescanning periodically for new processes.
func (ao *APIObserver) attachGoHTTP2Uprobes() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	// Map of uprobe short IDs → BPF programs.
	// For uretprobes, the key gets a "_ret" suffix.
	probeMap := map[string]*ebpf.Program{
		"server_handleStream":      ao.objs.KaUprobeServerHandleStream,
		"server_handleStream_ret":  ao.objs.KaUretprobeServerHandleStream,
		"transport_writeStatus":    ao.objs.KaUprobeTransportWriteStatus,
		"ClientConn_Invoke":        ao.objs.KaUprobeClientConnInvoke,
		"ClientConn_Invoke_ret":    ao.objs.KaUretprobeClientConnInvoke,
		"ClientConn_NewStream":     ao.objs.KaUprobeClientConnNewStream,
		"clientStream_RecvMsg_ret": ao.objs.KaUretprobeClientStreamRecvMsg,
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
				// Attach entry uprobe.
				if prog, ok := probeMap[shortID]; ok {
					l, err := attachUprobeWithFallback(ex, "", prog, addr)
					if err != nil {
						ao.Logger.Warnf("Failed to attach uprobe %s at 0x%x on %s: %v",
							shortID, addr, target.BinaryPath, err)
					} else {
						ao.links = append(ao.links, l)
						probeCount++
						ao.Logger.Printf("  uprobe/%s attached at 0x%x", shortID, addr)
					}
				}

				// Attach return uprobe (uretprobe) if it exists.
				retKey := shortID + "_ret"
				if retProg, ok := probeMap[retKey]; ok {
					l, err := attachUprobeWithFallback(ex, "", retProg, addr)
					if err != nil {
						ao.Logger.Warnf("Failed to attach uretprobe %s at 0x%x on %s: %v",
							retKey, addr, target.BinaryPath, err)
					} else {
						ao.links = append(ao.links, l)
						probeCount++
						ao.Logger.Printf("  uretprobe/%s attached at 0x%x", retKey, addr)
					}
				}
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

// attachGRPCCUprobes scans for gRPC-C (libgrpc.so) binaries and attaches
// the grpc_chttp2_maybe_complete_recv_initial_metadata uprobe.
// Runs as a background goroutine; never returns an error.
func (ao *APIObserver) attachGRPCCUprobes() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	attached := make(map[string]bool)

	// Trigger first scan immediately without blocking the select.
	doScan := make(chan struct{}, 1)
	doScan <- struct{}{}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ao.ctx.Done():
			return
		case <-doScan:
			ao.scanAndAttachGRPCC(attached)
		case <-ticker.C:
			ao.scanAndAttachGRPCC(attached)
		}
	}
}

// drainGRPCCEvents reads the gRPC-C ring buffer and processes path events.
func (ao *APIObserver) drainGRPCCEvents() {
	ao.wg.Add(1)
	defer ao.wg.Done()

	if ao.grpccEvents == nil {
		return
	}

	// Inner reader goroutine — NOT tracked in wg; exits via ErrClosed
	// when DestroyAPIObserver calls ao.grpccEvents.Close().
	go func() {
		for {
			record, err := ao.grpccEvents.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			select {
			case ao.grpccChannel <- record.RawSample:
			case <-ao.ctx.Done():
				return
			}
		}
	}()

	// Outer processing loop — tracked in wg; exits on ctx.Done().
	for {
		select {
		case <-ao.ctx.Done():
			return
		case raw := <-ao.grpccChannel:
			ao.processGRPCCEvent(raw)
		}
	}
}

// scanAndAttachGRPCC is the inner scan body, called from attachGRPCCUprobes.
func (ao *APIObserver) scanAndAttachGRPCC(attached map[string]bool) {
	targets, err := grpcc.ScanProc()
	if err != nil {
		ao.Logger.Warnf("gRPC-C proc scan error: %v", err)
		return
	}
	for _, target := range targets {
		if attached[target.LibPath] {
			continue
		}
		offsets, err := grpcc.OffsetsForLib(target.LibPath)
		if err != nil {
			ao.Logger.Warnf("gRPC-C: %v", err)
			continue
		}
		// Array map (max_entries=1) — key is always 0.
		if err := ao.objs.GrpccSymaddrsMap.Put(uint32(0), offsets); err != nil {
			ao.Logger.Warnf("gRPC-C: failed to write symaddrs for %s: %v", target.LibPath, err)
			continue
		}
		ex, err := link.OpenExecutable(target.LibPath)
		if err != nil {
			ao.Logger.Warnf("gRPC-C: failed to open %s: %v", target.LibPath, err)
			continue
		}
		l, err := ex.Uprobe(
			"grpc_chttp2_maybe_complete_recv_initial_metadata",
			ao.objs.KaUprobeGrpcC_recvInitialMetadataEntry,
			nil,
		)
		if err != nil {
			ao.Logger.Warnf("gRPC-C: uprobe attach failed on %s: %v", target.LibPath, err)
			continue
		}
		ao.links = append(ao.links, l)
		attached[target.LibPath] = true
		ao.Logger.Printf("gRPC-C uprobe attached to %s (PID %d)", target.LibPath, target.PID)
	}
}

// processGRPCCEvent decodes one ring-buffer sample and injects the
// captured gRPC-C method path into the correlator.
func (ao *APIObserver) processGRPCCEvent(raw []byte) {
	ev, err := events.ParseGRPCCHeaderEvent(raw)
	if err != nil {
		ao.Logger.Debugf("ParseGRPCCHeaderEvent error: %v", err)
		return
	}
	method := ev.MethodString()
	if method == "" {
		slog.Debug("gRPC-C uprobe: ignoring event with empty method", "pid", ev.PID)
		return
	}
	ao.correlator.InjectGRPCCEvent(ev.PID, ev.FD, ev.StreamID, method)
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
	if ao.grpccEvents != nil {
		if err := ao.grpccEvents.Close(); err != nil {
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
	ao.wg.Wait()
	return cleanupErr
}

// eNOTSUPP is errno 524 — the Linux kernel's internal "not supported" error
// returned by uprobe_register when the target address contains a trap instruction.
// It is not exported by golang.org/x/sys/unix so we define it directly.
const eNOTSUPP = syscall.Errno(524)

func attachUprobeWithFallback(
    ex *link.Executable,
    sym string,
    prog *ebpf.Program,
    addr uint64,
) (link.Link, error) {
    var opts *link.UprobeOptions
    if addr != 0 {
        opts = &link.UprobeOptions{Address: addr}
    }

    l, err := ex.Uprobe(sym, prog, opts)
    if err == nil {
        return l, nil
    }

    // Retry at addr+1 only when:
    //   (a) we have an explicit address to offset from (addr != 0), AND
    //   (b) the kernel rejected the address as a trap/NOP sled (errno 524).
    // When addr==0, cilium/ebpf resolves by symbol name; we have no known
    // base address to offset from, so retrying makes no sense.
    isNotSupp := errors.Is(err, eNOTSUPP) ||
        strings.Contains(err.Error(), "errno 524")

    if addr != 0 && isNotSupp {
        l2, err2 := ex.Uprobe(sym, prog, &link.UprobeOptions{Address: addr + 1})
        if err2 == nil {
            return l2, nil
        }
        // Return the original error — it's more informative than addr+1 failure.
    }

    return nil, err
}
