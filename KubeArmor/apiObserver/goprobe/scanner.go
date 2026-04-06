// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package goprobe discovers Go binaries using gRPC / net/http HTTP/2
// and resolves the symbol addresses + struct offsets needed by the
// BPF Go HTTP/2 uprobes (go_http2_trace.h).
//
// Adapted from Pixie's uprobe_manager.cc + uprobe_symaddrs.cc.
package goprobe

import (
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// shouldSkipBinaryPath returns true if this binary is a known high-churn tooling
// process that commonly exists on nodes (editor helpers, CLIs, Go toolchain).
//
// Attaching uprobes broadly is expensive and increases drop risk (replay timeouts).
// We prefer to skip these by default and focus on actual workload binaries.
func shouldSkipBinaryPath(hostPath string) bool {
	p := strings.TrimSpace(hostPath)
	if p == "" {
		return true
	}
	// procfs sometimes yields " (deleted)" suffix.
	p = strings.TrimSuffix(p, " (deleted)")

	base := filepath.Base(p)
	switch base {
	case "go", "gopls", "dlv", "kubectl", "k9s", "helm", "kind", "kustomize", "minikube":
		return true
	}

	// Skip the Go toolchain installation path explicitly.
	// This is frequently running during builds and is not a workload.
	if strings.Contains(p, "/usr/local/go/") || strings.Contains(p, "/usr/lib/go/") {
		return true
	}

	return false
}

// LocType mirrors BPF enum go_location_type.
const (
	LocInvalid  uint32 = 0
	LocStack    uint32 = 1
	LocRegister uint32 = 2
)

// ArgLocation matches BPF struct go_arg_location { type, offset }.
type ArgLocation struct {
	Type   uint32
	Offset int32
}

// InvalidLoc is returned for unresolved argument locations.
var InvalidLoc = ArgLocation{Type: LocInvalid, Offset: -1}

// Offset table indices — must match go_http2_symaddrs.h enum go_offset_kind.
const (
	GoOffGRPCStreamMethod       = 0
	GoOffGRPCStreamID           = 1
	GoOffGRPCTransportConn      = 2
	GoOffGRPCStatusS            = 3
	GoOffGRPCStatusCode         = 4
	GoOffFDSysfd                = 5
	GoOffConnFD                 = 6
	GoOffFDLaddr                = 7
	GoOffFDRaddr                = 8
	GoOffTCPAddrPort            = 9
	GoOffTCPAddrIP              = 10
	GoOffGRPCV160               = 11
	GoOffGRPCV169               = 12
	GoOffGRPCServerStreamStream = 13
	GoOffGRPCServerStreamST     = 14
	GoOffGRPCStreamST           = 15
	GoOffTLSConnConn            = 16
	GoOffMax                    = 17
)

// GoOffsetTable matches BPF struct go_offset_table.
// Populated per-binary and pushed to BPF map keyed by inode.
type GoOffsetTable struct {
	Offsets [GoOffMax]int64
}

// GoCommonSymaddrs is retained for backward compatibility but no longer
// used by the new OTel-style probes. The offset table replaces it.
type GoCommonSymaddrs struct {
	InternalSyscallConn   int64
	TlsConn               int64
	NetTCPConn            int64
	FD_SysfdOffset        int32
	TlsConnConnOffset     int32
	SyscallConnConnOffset int32
	G_goidOffset          int32
	G_addrOffset          int32
}

// GoUProbeTarget is a Go binary that has gRPC / HTTP/2 symbols.
type GoUProbeTarget struct {
	// PID that uses this binary.
	PID uint32
	// Host path to the ELF binary (resolved through /proc/PID/root).
	BinaryPath string
	// Inode of the binary (for offset table BPF map key).
	Inode uint64
	// Resolved symbol addresses for uprobe attachment.
	Symbols map[string]uint64
	// Offset table pushed to BPF map.
	OffsetTable GoOffsetTable
}

// TargetSymbols are the Go function symbols we want to attach uprobes to.
// Keys are short IDs used for probe attachment, values are candidate symbol names.
// Adapted from OpenTelemetry's go_grpc.c probe targets.
var TargetSymbols = map[string][]string{
	"server_handleStream": {
		"google.golang.org/grpc.(*Server).handleStream",
	},
	"transport_writeStatus": {
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus",
	},
	"ClientConn_Invoke": {
		"google.golang.org/grpc.(*ClientConn).Invoke",
	},
	"ClientConn_NewStream": {
		"google.golang.org/grpc.(*ClientConn).NewStream",
	},
	"clientStream_RecvMsg": {
		"google.golang.org/grpc.(*clientStream).RecvMsg",
	},
	// crypto/tls — Go TLS uprobes (Phase 2)
	"tls_Conn_Write": {
		"crypto/tls.(*Conn).Write",
	},
	"tls_Conn_Read": {
		"crypto/tls.(*Conn).Read",
	},
}

// TLSFuncCandidates returns candidate symbol names for Go crypto/tls probes.
func TLSFuncCandidates(shortID string) []string {
	switch shortID {
	case "tls_Conn_Write":
		return TargetSymbols["tls_Conn_Write"]
	case "tls_Conn_Read":
		return TargetSymbols["tls_Conn_Read"]
	default:
		return nil
	}
}

// ScanProc scans /proc for Go binaries that use gRPC or net/http HTTP/2.
// Returns a list of targets suitable for uprobe attachment.
func ScanProc() ([]GoUProbeTarget, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	// Track binary→PIDs to avoid redundant ELF analysis.
	type pidEntry struct {
		pid      uint32
		exePath  string
		hostPath string
	}
	binMap := make(map[string][]pidEntry)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		if pid == 0 {
			continue
		}
		exeLink := fmt.Sprintf("/proc/%d/exe", pid)
		exePath, err := os.Readlink(exeLink)
		if err != nil {
			continue
		}
		// Resolve through procfs root for containerised binaries.
		hostPath := fmt.Sprintf("/proc/%d/root%s", pid, exePath)
		if _, err := os.Stat(hostPath); err != nil {
			hostPath = exePath
		}
		binMap[hostPath] = append(binMap[hostPath], pidEntry{pid: pid, exePath: exePath, hostPath: hostPath})
	}

	var targets []GoUProbeTarget
	for hostPath, pids := range binMap {
		if shouldSkipBinaryPath(hostPath) {
			continue
		}

		if !isGoBinary(hostPath) {
			continue
		}

		// Open ELF and look for gRPC symbols.
		ef, err := elf.Open(hostPath)
		if err != nil {
			continue
		}

		syms, err := resolveSymbols(ef, hostPath)
		ef.Close()
		if err != nil {
			continue
		}
		if len(syms) == 0 {
			continue
		}

		slog.Info("Found Go HTTP/2 binary for uprobe",
			"path", hostPath, "pids", len(pids), "symbols", len(syms))

		// Build offset table with defaults.
		offTable := DefaultOffsetTable()

		// Detect gRPC version and apply version-specific offsets.
		grpcVer := GetGrpcLibVersion(hostPath)
		ApplyVersionOffsets(&offTable, grpcVer)

		// Resolve inode for BPF map key.
		var inode uint64
		if fi, err := os.Stat(hostPath); err == nil {
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
				inode = stat.Ino
			}
		}

		for _, pe := range pids {
			targets = append(targets, GoUProbeTarget{
				PID:         pe.pid,
				BinaryPath:  pe.hostPath,
				Inode:       inode,
				Symbols:     syms,
				OffsetTable: offTable,
			})
		}
	}

	return targets, nil
}

// ScanPID scans a single PID for Go HTTP/2 symbols.
func ScanPID(pid uint32) (*GoUProbeTarget, error) {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	exePath, err := os.Readlink(exeLink)
	if err != nil {
		return nil, fmt.Errorf("readlink %s: %w", exeLink, err)
	}
	hostPath := fmt.Sprintf("/proc/%d/root%s", pid, exePath)
	if _, err := os.Stat(hostPath); err != nil {
		hostPath = exePath
	}

	if !isGoBinary(hostPath) {
		return nil, fmt.Errorf("not a Go binary: %s", hostPath)
	}

	ef, err := elf.Open(hostPath)
	if err != nil {
		return nil, fmt.Errorf("open ELF %s: %w", hostPath, err)
	}
	defer ef.Close()

	syms, err := resolveSymbols(ef, hostPath)
	if err != nil {
		return nil, err
	}
	if len(syms) == 0 {
		return nil, fmt.Errorf("no gRPC/HTTP2 symbols in %s", hostPath)
	}

	offTable := DefaultOffsetTable()
	grpcVer := GetGrpcLibVersion(hostPath)
	ApplyVersionOffsets(&offTable, grpcVer)

	var inode uint64
	if fi, err := os.Stat(hostPath); err == nil {
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			inode = stat.Ino
		}
	}

	return &GoUProbeTarget{
		PID:         pid,
		BinaryPath:  hostPath,
		Inode:       inode,
		Symbols:     syms,
		OffsetTable: offTable,
	}, nil
}

// isGoBinary checks if a binary contains Go build info.
func isGoBinary(path string) bool {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return false
	}
	return info.GoVersion != ""
}

// resolveSymbols looks up the target function symbols in the ELF binary.
// Returns a map of short_id → virtual address.
func resolveSymbols(ef *elf.File, path string) (map[string]uint64, error) {
	allSyms, err := ef.Symbols()
	if err != nil || len(allSyms) == 0 {
		// Fallback for binaries with limited regular symbol tables.
		dynSyms, dynErr := ef.DynamicSymbols()
		if dynErr != nil {
			if err != nil {
				return nil, fmt.Errorf("read symbols from %s: %w", path, err)
			}
			return nil, fmt.Errorf("read dynamic symbols from %s: %w", path, dynErr)
		}
		allSyms = dynSyms
	}

	// Build a map of name → address for quick lookup.
	symMap := make(map[string]uint64, len(allSyms))
	for _, s := range allSyms {
		if s.Value != 0 {
			symMap[s.Name] = s.Value
		}
	}

	result := make(map[string]uint64)
	for shortID, candidates := range TargetSymbols {
		for _, candidate := range candidates {
			// Try exact match first, then vendor-prefixed match.
			if addr, ok := symMap[candidate]; ok {
				off, ok := vaddrToFileOffsetForELF(ef, addr)
				if ok {
					result[shortID] = off
				}
				break
			}
			// Try with vendor prefix: look for suffix match.
			for name, addr := range symMap {
				if strings.HasSuffix(name, candidate) {
					off, ok := vaddrToFileOffsetForELF(ef, addr)
					if ok {
						result[shortID] = off
					}
					break
				}
			}
		}
	}

	return result, nil
}

// vaddrToFileOffsetForELF translates a virtual address to file offset using PT_LOAD segments.
// perf uprobes require file offsets.
func vaddrToFileOffsetForELF(ef *elf.File, vaddr uint64) (uint64, bool) {
	for _, p := range ef.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		end := p.Vaddr + p.Filesz
		if vaddr >= p.Vaddr && vaddr < end {
			return p.Off + (vaddr - p.Vaddr), true
		}
	}
	return 0, false
}

// resolveItableAddrs is retained for backward compatibility.
// The new OTel-style probes do not require itable resolution.
func resolveItableAddrs(ef *elf.File, common *GoCommonSymaddrs) {
	allSyms, err := ef.Symbols()
	if err != nil {
		return
	}

	for _, s := range allSyms {
		if s.Value == 0 {
			continue
		}
		name := s.Name

		for _, prefix := range []string{"go.itab.", "go:itab."} {
			if strings.HasPrefix(name, prefix) {
				rest := name[len(prefix):]
				switch {
				case strings.Contains(rest, "internal.syscallConn,net.Conn"):
					common.InternalSyscallConn = int64(s.Value)
				case strings.Contains(rest, "crypto/tls.Conn,net.Conn"):
					common.TlsConn = int64(s.Value)
				case strings.Contains(rest, "net.TCPConn,net.Conn"):
					common.NetTCPConn = int64(s.Value)
				}
			}
		}
	}
}

// FindGoHTTP2PIDs returns PIDs of processes using Go gRPC/HTTP2.
// Useful for targeted scanning instead of full /proc scan.
func FindGoHTTP2PIDs() ([]uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var pids []uint32
	seen := make(map[string]bool)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid == 0 {
			continue
		}
		exeLink := fmt.Sprintf("/proc/%d/exe", pid)
		target, err := filepath.EvalSymlinks(exeLink)
		if err != nil {
			continue
		}
		if seen[target] {
			pids = append(pids, pid)
			continue
		}
		if isGoBinary(target) {
			ef, err := elf.Open(target)
			if err != nil {
				continue
			}
			syms, _ := resolveSymbols(ef, target)
			ef.Close()
			if len(syms) > 0 {
				seen[target] = true
				pids = append(pids, pid)
			}
		}
	}

	return pids, nil
}

// ErrNotGoBinary is returned when a binary is not a Go binary.
var ErrNotGoBinary = errors.New("not a Go binary")
