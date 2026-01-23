// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"fmt"
	"strings"
)

// IsGRPCRequest checks if data looks like a gRPC request
// gRPC uses HTTP/2 with content-type: application/grpc
func IsGRPCRequest(data []byte, headers map[string]string) bool {
	if headers == nil {
		return false
	}

	// Check for gRPC content type
	contentType, ok := headers["content-type"]
	if !ok {
		contentType, ok = headers["Content-Type"]
	}

	if ok && strings.HasPrefix(contentType, "application/grpc") {
		return true
	}

	return false
}

// ParseGRPCMethod extracts the gRPC method from headers
// gRPC method is in the :path pseudo-header (HTTP/2)
func ParseGRPCMethod(headers map[string]string) string {
	// Try :path first (HTTP/2 pseudo-header)
	if path, ok := headers[":path"]; ok {
		return path
	}

	// Fallback to regular path header
	if path, ok := headers["path"]; ok {
		return path
	}

	return ""
}

// ParseGRPCStatus extracts gRPC status from headers
func ParseGRPCStatus(headers map[string]string) int {
	// gRPC status is in grpc-status header
	if status, ok := headers["grpc-status"]; ok {
		// Convert to int
		var statusCode int
		if _, err := fmt.Sscanf(status, "%d", &statusCode); err == nil {
			return statusCode
		}
	}

	return 0 // OK status
}
