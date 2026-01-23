// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"strings"
)

// FilterConfig defines filtering rules for API events
type FilterConfig struct {
	ExcludePaths      []string
	ExcludeUserAgents []string
	ExcludeNamespaces []string
}

// DefaultFilterConfig returns the default filter configuration
// with common health check, probe, and metrics patterns
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		ExcludePaths: []string{
			"/health",
			"/healthz",
			"/ready",
			"/readyz",
			"/livez",
			"/metrics",
			"/stats/prometheus",
			"/_status/healthz",
		},
		ExcludeUserAgents: []string{
			"kube-probe",
			"Prometheus",
			"prometheus",
			"GoogleHC",
		},
		ExcludeNamespaces: []string{
			"kube-system",
			"kube-public",
			"kube-node-lease",
		},
	}
}

// ShouldFilterRequest determines if a request should be filtered out
// Returns true if the request matches any filter criteria
func (f *FilterConfig) ShouldFilterRequest(path, userAgent, namespace string) bool {
	if f.ShouldFilterByPath(path) {
		return true
	}
	if f.ShouldFilterByUserAgent(userAgent) {
		return true
	}
	if f.ShouldFilterByNamespace(namespace) {
		return true
	}
	return false
}

// ShouldFilterByPath checks if the request path matches filter patterns
func (f *FilterConfig) ShouldFilterByPath(path string) bool {
	for _, excludePath := range f.ExcludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

// ShouldFilterByUserAgent checks if the user agent matches filter patterns
func (f *FilterConfig) ShouldFilterByUserAgent(userAgent string) bool {
	for _, excludeUA := range f.ExcludeUserAgents {
		if strings.Contains(userAgent, excludeUA) {
			return true
		}
	}
	return false
}

// ShouldFilterByNamespace checks if the namespace should be filtered
func (f *FilterConfig) ShouldFilterByNamespace(namespace string) bool {
	for _, excludeNS := range f.ExcludeNamespaces {
		if namespace == excludeNS {
			return true
		}
	}
	return false
}
