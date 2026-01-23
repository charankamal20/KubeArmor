// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// ParseHTTPRequest parses raw HTTP request data
func ParseHTTPRequest(data []byte) (*HTTPRequest, error) {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Read request line
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}

	parts := strings.SplitN(strings.TrimSpace(requestLine), " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid HTTP request line")
	}

	req := &HTTPRequest{
		Method:  parts[0],
		Path:    parts[1],
		Version: parts[2],
		Headers: make(map[string]string),
	}

	// Read headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}

		headerParts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(headerParts) == 2 {
			req.Headers[strings.TrimSpace(headerParts[0])] = strings.TrimSpace(headerParts[1])
		}
	}

	// Read body (remaining data)
	body := make([]byte, reader.Buffered())
	reader.Read(body)
	req.Body = body

	return req, nil
}

// ParseHTTPResponse parses raw HTTP response data
func ParseHTTPResponse(data []byte) (*HTTPResponse, error) {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read status line: %w", err)
	}

	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid HTTP response line")
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %w", err)
	}

	status := ""
	if len(parts) >= 3 {
		status = parts[2]
	}

	resp := &HTTPResponse{
		StatusCode: statusCode,
		Status:     status,
		Version:    parts[0],
		Headers:    make(map[string]string),
	}

	// Read headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}

		headerParts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(headerParts) == 2 {
			resp.Headers[strings.TrimSpace(headerParts[0])] = strings.TrimSpace(headerParts[1])
		}
	}

	// Read body (remaining data)
	body := make([]byte, reader.Buffered())
	reader.Read(body)
	resp.Body = body

	return resp, nil
}

// IsHTTPRequest checks if data looks like an HTTP request
func IsHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for common HTTP methods
	methods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "PATC", "OPTI", "TRAC", "CONN"}
	prefix := string(data[:4])
	for _, method := range methods {
		if strings.HasPrefix(prefix, method) {
			return true
		}
	}
	return false
}

// IsHTTPResponse checks if data looks like an HTTP response
func IsHTTPResponse(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	// Check for HTTP version prefix
	return strings.HasPrefix(string(data[:5]), "HTTP/")
}
