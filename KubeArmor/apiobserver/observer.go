// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	pb "github.com/kubearmor/KubeArmor/KubeArmor/apiobserver/sentryflow"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

// APIObserver manages eBPF-based API traffic observation
type APIObserver struct {
	// eBPF objects and links
	objs       *ebpf.Collection
	links      []link.Link
	ringReader *ringbuf.Reader

	// Event processing
	eventChan chan *pb.APIEvent
	stopChan  chan struct{}
	wg        sync.WaitGroup

	// Request-response correlation
	pendingRequests map[uint64]*pendingRequest
	requestsMutex   sync.Mutex

	// Logger
	logger *fd.Feeder

	// Node information
	clusterName string
	hostName    string

	// Filtering
	filterConfig *FilterConfig
}

// pendingRequest tracks requests waiting for responses
type pendingRequest struct {
	timestamp    int64
	method       string
	path         string
	headers      map[string]string
	body         []byte
	protocol     string
	srcPod       string
	srcNs        string
	srcContainer string
	destIP       string
	destPort     uint32
}

// NewAPIObserver creates a new API observer instance
func NewAPIObserver(logger *fd.Feeder, clusterName, hostName string) *APIObserver {
	return &APIObserver{
		eventChan:       make(chan *pb.APIEvent, 1000),
		stopChan:        make(chan struct{}),
		pendingRequests: make(map[uint64]*pendingRequest),
		logger:          logger,
		clusterName:     clusterName,
		hostName:        hostName,
		filterConfig:    DefaultFilterConfig(),
	}
}

// Start initializes and starts the API observer
func (o *APIObserver) Start() error {
	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec("/sys/fs/bpf/http_tracer.bpf.o")
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	o.objs, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	// Attach tracepoint for socket state tracking
	tpLink, err := link.Tracepoint("sock", "inet_sock_set_state", o.objs.Programs["trace_inet_sock_set_state"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint: %w", err)
	}
	o.links = append(o.links, tpLink)

	// Attach kprobe for tcp_sendmsg
	sendLink, err := link.Kprobe("tcp_sendmsg", o.objs.Programs["kprobe_tcp_sendmsg"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_sendmsg kprobe: %w", err)
	}
	o.links = append(o.links, sendLink)

	// Attach kprobe/kretprobe for tcp_recvmsg
	recvLink, err := link.Kprobe("tcp_recvmsg", o.objs.Programs["kprobe_tcp_recvmsg"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_recvmsg kprobe: %w", err)
	}
	o.links = append(o.links, recvLink)

	recvRetLink, err := link.Kretprobe("tcp_recvmsg", o.objs.Programs["kretprobe_tcp_recvmsg"], nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_recvmsg kretprobe: %w", err)
	}
	o.links = append(o.links, recvRetLink)

	// Open ring buffer reader
	o.ringReader, err = ringbuf.NewReader(o.objs.Maps["events"])
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	// Start event processing
	o.wg.Add(1)
	go o.processEvents()

	o.logger.Print("API Observer started successfully")
	return nil
}

// Stop stops the API observer and cleans up resources
func (o *APIObserver) Stop() error {
	close(o.stopChan)
	o.wg.Wait()

	// Close ring buffer reader
	if o.ringReader != nil {
		o.ringReader.Close()
	}

	// Detach all links
	for _, l := range o.links {
		l.Close()
	}

	// Close eBPF objects
	if o.objs != nil {
		o.objs.Close()
	}

	close(o.eventChan)
	o.logger.Print("API Observer stopped")
	return nil
}

// GetEventChannel returns the channel for consuming API events
func (o *APIObserver) GetEventChannel() chan *pb.APIEvent {
	return o.eventChan
}

// processEvents reads from ring buffer and processes events
func (o *APIObserver) processEvents() {
	defer o.wg.Done()

	for {
		select {
		case <-o.stopChan:
			return
		default:
			record, err := o.ringReader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				o.logger.Warnf("Error reading from ring buffer: %v", err)
				continue
			}

			// Parse event
			event := o.parseDataEvent(record.RawSample)
			if event == nil {
				continue
			}

			// Process based on direction
			if event.Direction == DirEgress {
				o.handleRequest(event)
			} else {
				o.handleResponse(event)
			}
		}
	}
}

// parseDataEvent parses raw bytes into DataEvent
func (o *APIObserver) parseDataEvent(data []byte) *DataEvent {
	if len(data) < 48 { // Minimum header size
		return nil
	}

	event := &DataEvent{}
	event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	event.PID = binary.LittleEndian.Uint32(data[8:12])
	event.TID = binary.LittleEndian.Uint32(data[12:16])
	event.SrcIP = binary.LittleEndian.Uint32(data[16:20])
	event.DstIP = binary.LittleEndian.Uint32(data[20:24])
	event.SrcPort = binary.LittleEndian.Uint16(data[24:26])
	event.DstPort = binary.LittleEndian.Uint16(data[26:28])
	event.DataLen = binary.LittleEndian.Uint32(data[28:32])
	event.Direction = data[32]
	event.SockPtr = binary.LittleEndian.Uint64(data[33:41])

	// Copy payload
	payloadLen := int(event.DataLen)
	if payloadLen > 4096 {
		payloadLen = 4096
	}
	if len(data) >= 41+payloadLen {
		copy(event.Payload[:], data[41:41+payloadLen])
	}

	return event
}

// handleRequest processes egress (request) events
func (o *APIObserver) handleRequest(event *DataEvent) {
	payload := event.Payload[:event.DataLen]

	// Try to parse as HTTP
	if IsHTTPRequest(payload) {
		req, err := ParseHTTPRequest(payload)
		if err != nil {
			o.logger.Warnf("Failed to parse HTTP request: %v", err)
			return
		}

		protocol := ProtocolHTTP
		if IsGRPCRequest(payload, req.Headers) {
			protocol = ProtocolGRPC
		}

		// Apply userspace filtering
		userAgent := req.Headers["User-Agent"]
		if userAgent == "" {
			userAgent = req.Headers["user-agent"]
		}
		// TODO: Get namespace from container metadata enrichment
		if o.filterConfig.ShouldFilterRequest(req.Path, userAgent, "") {
			return // Filtered out
		}

		// Store pending request
		o.requestsMutex.Lock()
		o.pendingRequests[event.SockPtr] = &pendingRequest{
			timestamp: int64(event.Timestamp),
			method:    req.Method,
			path:      req.Path,
			headers:   req.Headers,
			body:      req.Body,
			protocol:  protocol,
			destIP:    ipToString(event.DstIP),
			destPort:  uint32(event.DstPort),
			// TODO: Enrich with container metadata from PID
		}
		o.requestsMutex.Unlock()
	}
}

// handleResponse processes ingress (response) events
func (o *APIObserver) handleResponse(event *DataEvent) {
	payload := event.Payload[:event.DataLen]

	// Try to parse as HTTP response
	if IsHTTPResponse(payload) {
		resp, err := ParseHTTPResponse(payload)
		if err != nil {
			o.logger.Warnf("Failed to parse HTTP response: %v", err)
			return
		}

		// Find matching request
		o.requestsMutex.Lock()
		req, ok := o.pendingRequests[event.SockPtr]
		if !ok {
			o.requestsMutex.Unlock()
			o.logger.Warnf("No matching request found for response (sock_ptr: %d)", event.SockPtr)
			return
		}
		delete(o.pendingRequests, event.SockPtr)
		o.requestsMutex.Unlock()

		// Create SentryFlow APIEvent
		apiEvent := &pb.APIEvent{
			Metadata: &pb.Metadata{
				Timestamp:       uint64(req.timestamp),
				NodeName:        o.hostName,
				ReceiverName:    "KubeArmor",
				ReceiverVersion: "v1.0", // TODO: Get actual version
			},
			Source: &pb.Workload{
				Name:      req.srcPod,
				Namespace: req.srcNs,
				Ip:        ipToString(event.SrcIP),
				Port:      int32(event.SrcPort),
			},
			Destination: &pb.Workload{
				Name:      "", // TODO: Resolve from IP
				Namespace: "",
				Ip:        req.destIP,
				Port:      int32(req.destPort),
			},
			Request: &pb.Request{
				Headers: req.headers,
				Body:    string(req.body),
			},
			Response: &pb.Response{
				Headers: resp.Headers,
				Body:    string(resp.Body),
			},
			Protocol: req.protocol,
		}

		// Send to channel
		select {
		case o.eventChan <- apiEvent:
		default:
			o.logger.Warn("Event channel full, dropping event")
		}
	}
}

// ipToString converts uint32 IP to string
func ipToString(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}
