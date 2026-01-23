// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package apiobserver provides HTTP/gRPC API traffic observability using eBPF
package apiobserver

// DataEvent represents a raw eBPF event from the ring buffer
type DataEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	DataLen   uint32
	Direction uint8
	SockPtr   uint64
	Payload   [4096]byte
}

// ConnectionInfo tracks active TCP connections
type ConnectionInfo struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

// Direction constants
const (
	DirEgress  = 0
	DirIngress = 1
)

// Protocol types
const (
	ProtocolHTTP = "HTTP"
	ProtocolGRPC = "gRPC"
)

// HTTPRequest represents a parsed HTTP request
type HTTPRequest struct {
	Method  string
	Path    string
	Version string
	Headers map[string]string
	Body    []byte
}

// HTTPResponse represents a parsed HTTP response
type HTTPResponse struct {
	StatusCode int
	Status     string
	Version    string
	Headers    map[string]string
	Body       []byte
}

// APICall represents a correlated request-response pair
type APICall struct {
	Timestamp       int64
	SourcePod       string
	SourceNamespace string
	SourceContainer string
	DestIP          string
	DestPort        uint32
	Method          string
	Path            string
	StatusCode      int32
	Headers         map[string]string
	RequestBody     []byte
	ResponseBody    []byte
	Protocol        string
	SockPtr         uint64
	ClusterName     string
	HostName        string
}
