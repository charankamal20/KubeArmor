// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
//
// ssl/symaddrs.go — SSL library discovery and struct offset detection.
//
// Pixie-style approach: scan /proc/<pid>/maps to find loaded SSL libraries,
// classify them, and resolve struct field offsets for BPF FD extraction.
//
// Supports:
//   - OpenSSL 1.0, 1.1, 3.x (libssl.so.*)
//   - BoringSSL (libnetty_tcnative, libconscrypt_openjdk_jni)
//   - Python (libpython3.x.so — statically links OpenSSL)
//
// Reference: Pixie uprobe_manager.cc L310-L339, uprobe_symaddrs.cc
package ssl

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ──────────────────────────────────────────────────────────────────
// BPF struct offsets
// ──────────────────────────────────────────────────────────────────

// SymAddrs holds the two field offsets the BPF uprobe needs to extract
// a file descriptor from an SSL*.
//
// BPF usage (openssl_trace.h):
//
//	rbio = *(void**)((u8*)ssl  + ssl_rbio_offset)  // SSL → BIO*
//	fd   = *(int*)  ((u8*)rbio + bio_num_offset)   // BIO → fd
//
// MUST stay in sync with struct ssl_symaddrs in common/structs.h.
type SymAddrs struct {
	SSLRBIOOffset int32 // offsetof(SSL, rbio)
	BIONumOffset  int32 // offsetof(BIO, num)
}

// versionOffsets maps an OpenSSL/BoringSSL version prefix to the correct
// struct field offsets.
//
// Values verified against OpenSSL source:
//
//	1.0.x  ssl/ssl_locl.h   — ssl→rbio at +96,  bio→num at +40
//	1.1.x  ssl/ssl_local.h  — ssl→rbio at +16,  bio→num at +48
//	3.x    ssl/ssl_local.h  — same layout as 1.1.x
//	BoringSSL               — ssl→rbio at +0x18, bio→num at +0x18
var versionOffsets = map[string]SymAddrs{
	"OpenSSL 1.0": {SSLRBIOOffset: 96, BIONumOffset: 40},
	"OpenSSL 1.1": {SSLRBIOOffset: 16, BIONumOffset: 48},
	"OpenSSL 3.":  {SSLRBIOOffset: 16, BIONumOffset: 48},
	"BoringSSL":   {SSLRBIOOffset: 0x18, BIONumOffset: 0x18},
}

// ──────────────────────────────────────────────────────────────────
// FD access method
// ──────────────────────────────────────────────────────────────────

// FDAccessMethod controls how the BPF uprobe extracts the file descriptor.
type FDAccessMethod int

const (
	// FDMethodNestedSyscall: Track FD from the underlying read()/write()
	// syscall that occurs while SSL_read/SSL_write is on the stack.
	// Used for OpenSSL and Python (where BIO does real I/O).
	FDMethodNestedSyscall FDAccessMethod = iota

	// FDMethodUserSpaceOffsets: Walk ssl→rbio→num using struct offsets.
	// Used for BoringSSL (Netty tcnative, Conscrypt) where the BIO
	// doesn't do real I/O syscalls.
	FDMethodUserSpaceOffsets
)

// ──────────────────────────────────────────────────────────────────
// SSL library match result
// ──────────────────────────────────────────────────────────────────

// SSLLibMatch represents a discovered SSL library in a process.
type SSLLibMatch struct {
	// HostPath is the absolute path to the library on the host filesystem
	// (resolved via /proc/<pid>/root/...).
	HostPath string

	// LibType classifies the library (for logging/metrics).
	LibType string

	// FDMethod indicates which BPF FD extraction path to use.
	FDMethod FDAccessMethod

	// Offsets are the BPF struct field offsets (only used in UserSpaceOffsets path).
	Offsets SymAddrs
}

// ──────────────────────────────────────────────────────────────────
// Library matchers (from Pixie uprobe_manager.cc L310-L339)
// ──────────────────────────────────────────────────────────────────

type matchStyle int

const (
	matchContains matchStyle = iota
	matchEndsWith
)

type libMatcher struct {
	pattern  string
	style    matchStyle
	libType  string
	fdMethod FDAccessMethod
}

// libMatchers defines the search patterns, ordered by priority.
// More specific matchers (Netty, Conscrypt, Python) come before
// the generic libssl.so matchers to avoid false positives.
var libMatchers = []libMatcher{
	// Java / Netty tcnative (BoringSSL JNI wrapper)
	{pattern: "libnetty_tcnative_linux_x86", style: matchContains,
		libType: "netty_tcnative", fdMethod: FDMethodUserSpaceOffsets},
	{pattern: "libnetty_tcnative_linux_aarch", style: matchContains,
		libType: "netty_tcnative", fdMethod: FDMethodUserSpaceOffsets},
	{pattern: "libnetty_tcnative", style: matchContains,
		libType: "netty_tcnative", fdMethod: FDMethodUserSpaceOffsets},
	// Java / gRPC Conscrypt (BoringSSL JNI wrapper)
	{pattern: "libconscrypt_openjdk_jni", style: matchContains,
		libType: "conscrypt", fdMethod: FDMethodUserSpaceOffsets},
	// Python — libpython statically links OpenSSL
	{pattern: "libpython", style: matchContains,
		libType: "python", fdMethod: FDMethodNestedSyscall},
	// OpenSSL 1.0
	{pattern: "libssl.so.1.0", style: matchEndsWith,
		libType: "openssl_1_0", fdMethod: FDMethodNestedSyscall},
	{pattern: "libssl.so.10", style: matchEndsWith,
		libType: "openssl_1_0", fdMethod: FDMethodNestedSyscall},
	// OpenSSL 1.1
	{pattern: "libssl.so.1.1", style: matchEndsWith,
		libType: "openssl_1_1", fdMethod: FDMethodNestedSyscall},
	// OpenSSL 3.x
	{pattern: "libssl.so.3", style: matchEndsWith,
		libType: "openssl_3", fdMethod: FDMethodNestedSyscall},
	// Direct BoringSSL/AWS-LC style names
	{pattern: "libboringssl", style: matchContains,
		libType: "boringssl", fdMethod: FDMethodUserSpaceOffsets},
	{pattern: "libaws-lc", style: matchContains,
		libType: "aws_lc", fdMethod: FDMethodUserSpaceOffsets},
	// Generic libssl soname in distroless/minimal images.
	{pattern: "libssl.so", style: matchEndsWith,
		libType: "openssl_generic", fdMethod: FDMethodNestedSyscall},
}

// ──────────────────────────────────────────────────────────────────
// /proc/<pid>/maps scanning (Pixie-style)
// ──────────────────────────────────────────────────────────────────

// DiscoverSSLLibsForPID scans /proc/<pid>/maps to find mapped SSL-related
// libraries. Returns a slice of matches, one per unique library path.
//
// For container processes, the host path is derived as:
//
//	/proc/<pid>/root/<container-relative-path>
//
// This handles mount namespaces transparently.
func DiscoverSSLLibsForPID(pid uint32) []SSLLibMatch {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	hasSystemSSL := false
	var matches []SSLLibMatch

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// /proc/PID/maps format: addr perms offset dev inode pathname
		// Only executable mappings matter for uprobes
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		pathname := fields[len(fields)-1]
		if !strings.HasPrefix(pathname, "/") {
			continue
		}

		// Check if this is a system libssl (not via libpython)
		base := filepath.Base(pathname)
		if strings.HasPrefix(base, "libssl.so") {
			hasSystemSSL = true
		}

		for _, m := range libMatchers {
			matched := false
			switch m.style {
			case matchContains:
				matched = strings.Contains(base, m.pattern)
			case matchEndsWith:
				matched = strings.HasSuffix(base, m.pattern)
			}
			if !matched {
				continue
			}
			// Resolve host path for containers
			hostPath := fmt.Sprintf("/proc/%d/root%s", pid, pathname)

			if seen[hostPath] {
				break
			}
			seen[hostPath] = true

			match := SSLLibMatch{
				HostPath: hostPath,
				LibType:  m.libType,
				FDMethod: m.fdMethod,
			}

			// For userspace offset method, detect offsets from ELF
			if m.fdMethod == FDMethodUserSpaceOffsets {
				offsets, err := OffsetsForLib(hostPath)
				if err != nil {
					// Default BoringSSL offsets
					offsets = versionOffsets["BoringSSL"]
				}
				match.Offsets = offsets
			}

			matches = append(matches, match)
			break // One matcher per pathname
		}
	}

	// Python dual-linkage check: if the process has a system libssl.so
	// mapped AND a libpython match, skip the libpython match (the process
	// is using system OpenSSL, not the one bundled in libpython).
	if hasSystemSSL {
		filtered := matches[:0]
		for _, m := range matches {
			if m.LibType != "python" {
				filtered = append(filtered, m)
			}
		}
		matches = filtered
	}

	return matches
}

// ──────────────────────────────────────────────────────────────────
// ELF version detection (retained from original symaddrs.go)
// ──────────────────────────────────────────────────────────────────

// OffsetsForLib detects the OpenSSL version embedded in the given shared
// library and returns the struct field offsets needed by the BPF uprobe.
func OffsetsForLib(libPath string) (SymAddrs, error) {
	version, err := versionStringFromELF(libPath)
	if err != nil {
		return SymAddrs{}, fmt.Errorf("reading OpenSSL version from %s: %w", libPath, err)
	}

	for prefix, offsets := range versionOffsets {
		if strings.HasPrefix(version, prefix) {
			return offsets, nil
		}
	}

	// Fallback: use filename (SONAME suffix).
	filename := filepath.Base(libPath)
	if strings.Contains(filename, "libssl.so.3") {
		return versionOffsets["OpenSSL 3."], nil
	} else if strings.Contains(filename, "libssl.so.1.1") {
		return versionOffsets["OpenSSL 1.1"], nil
	} else if strings.Contains(filename, "libssl.so.1.0") {
		return versionOffsets["OpenSSL 1.0"], nil
	} else if strings.Contains(filename, "libssl.so") {
		// Generic soname fallback defaults to modern OpenSSL layout.
		return versionOffsets["OpenSSL 3."], nil
	}

	return SymAddrs{}, fmt.Errorf(
		"unsupported OpenSSL version %q (and filename %q not recognized)",
		version, filename,
	)
}

// versionStringFromELF scans the .rodata section of libPath for an
// OPENSSL_VERSION_TEXT string (e.g. "OpenSSL 3.0.2 15 Mar 2022").
func versionStringFromELF(libPath string) (string, error) {
	f, err := elf.Open(libPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sec := f.Section(".rodata")
	if sec == nil {
		return "", fmt.Errorf("%s has no .rodata section", libPath)
	}

	raw, err := sec.Data()
	if err != nil {
		return "", fmt.Errorf("reading .rodata from %s: %w", libPath, err)
	}

	s := string(raw)
	for _, prefix := range []string{"OpenSSL ", "BoringSSL"} {
		idx := strings.Index(s, prefix)
		if idx < 0 {
			continue
		}
		tail := s[idx:]
		end := strings.IndexByte(tail, 0)
		if end < 0 || end > 128 {
			end = 128
		}
		return tail[:end], nil
	}

	return "", fmt.Errorf("OpenSSL version string not found in .rodata of %s", libPath)
}

// ──────────────────────────────────────────────────────────────────
// Legacy API (retained for backward compatibility)
// ──────────────────────────────────────────────────────────────────

// libSSLGlobs lists glob patterns covering common libssl install paths.
var libSSLGlobs = []string{
	"/usr/lib/x86_64-linux-gnu/libssl.so.*",
	"/usr/lib/aarch64-linux-gnu/libssl.so.*",
	"/usr/lib64/libssl.so.*",
	"/usr/lib/libssl.so.*",
	"/lib/x86_64-linux-gnu/libssl.so.*",
	"/lib/aarch64-linux-gnu/libssl.so.*",
	"/lib64/libssl.so.*",
	"/usr/local/lib/libssl.so.*",
	"/usr/local/lib64/libssl.so.*",
}

// LibSSLPaths returns all concrete libssl.so.* paths found on the system.
func LibSSLPaths() ([]string, error) {
	seen := make(map[string]struct{})
	var result []string

	for _, pattern := range libSSLGlobs {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if _, dup := seen[m]; !dup {
				seen[m] = struct{}{}
				result = append(result, m)
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("libssl.so not found on system (checked %d glob patterns)",
			len(libSSLGlobs))
	}
	return result, nil
}
