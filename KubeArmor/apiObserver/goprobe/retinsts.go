// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package goprobe

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

type symbolInfo struct {
	Addr uint64
	Size uint64
}

// findFuncSymbol locates the function symbol by exact or suffix match and returns its address+size.
func findFuncSymbol(ef *elf.File, candidates []string) (*symbolInfo, error) {
	// Try regular symbols first, then dynamic symbols as fallback.
	syms, _ := ef.Symbols()
	if len(syms) == 0 {
		syms, _ = ef.DynamicSymbols()
	}
	if len(syms) == 0 {
		return nil, fmt.Errorf("no symbols available")
	}

	// Build a quick map for exact matches.
	symMap := make(map[string]elf.Symbol, len(syms))
	for _, s := range syms {
		if s.Value != 0 {
			symMap[s.Name] = s
		}
	}

	for _, cand := range candidates {
		if s, ok := symMap[cand]; ok {
			return &symbolInfo{Addr: s.Value, Size: s.Size}, nil
		}
	}

	// Suffix match for vendor-prefixed names.
	for _, cand := range candidates {
		for name, s := range symMap {
			if len(name) >= len(cand) && name[len(name)-len(cand):] == cand {
				return &symbolInfo{Addr: s.Value, Size: s.Size}, nil
			}
		}
	}

	return nil, fmt.Errorf("symbol not found")
}

// vaddrToFileOffset translates an ELF virtual address into a file offset
// using PT_LOAD segments. perf uprobes expect file offsets, not VAs.
func vaddrToFileOffset(ef *elf.File, vaddr uint64) (uint64, bool) {
	for _, p := range ef.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		va := p.Vaddr
		// Use Filesz here: we must map to bytes that exist in the file.
		end := va + p.Filesz
		if vaddr >= va && vaddr < end {
			return p.Off + (vaddr - va), true
		}
	}
	return 0, false
}

// FuncRetInstOffsets returns file offsets of all RET instructions within the function.
// This matches Pixie's "kReturnInsts" model used for Go crypto/tls tracing.
func FuncRetInstOffsets(binaryPath string, candidates []string) ([]uint64, error) {
	ef, err := elf.Open(binaryPath)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	si, err := findFuncSymbol(ef, candidates)
	if err != nil {
		return nil, fmt.Errorf("find func symbol: %w", err)
	}
	if si.Addr == 0 || si.Size == 0 {
		return nil, fmt.Errorf("invalid symbol addr/size: addr=0x%x size=%d", si.Addr, si.Size)
	}
	// Pixie safety bound: these symbols are ~2KiB; allow 100x headroom.
	if si.Size > 100*2048 {
		return nil, fmt.Errorf("refusing retinst scan: symbol size too large (%d bytes)", si.Size)
	}

	// Read function bytes via file offset so we can also validate segment mapping.
	funcOff, ok := vaddrToFileOffset(ef, si.Addr)
	if !ok {
		return nil, fmt.Errorf("failed VA->file offset for func start: 0x%x", si.Addr)
	}

	f, err := os.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()
	if _, err := f.Seek(int64(funcOff), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek func offset: %w", err)
	}
	code := make([]byte, si.Size)
	if _, err := io.ReadFull(f, code); err != nil {
		return nil, fmt.Errorf("read func bytes: %w", err)
	}

	// Find RET instruction VAs first, then translate each to file offset.
	var retVAs []uint64
	switch runtime.GOARCH {
	case "amd64":
		retVAs, err = findRetInstsAMD64(code, si.Addr)
	case "arm64":
		retVAs, err = findRetInstsARM64(code, si.Addr)
	default:
		return nil, fmt.Errorf("unsupported arch for retinst scan: %s", runtime.GOARCH)
	}
	if err != nil {
		return nil, err
	}

	retOffs := make([]uint64, 0, len(retVAs))
	seen := make(map[uint64]struct{}, len(retVAs))
	for _, va := range retVAs {
		off, ok := vaddrToFileOffset(ef, va)
		if !ok {
			continue
		}
		if _, dup := seen[off]; dup {
			continue
		}
		seen[off] = struct{}{}
		retOffs = append(retOffs, off)
	}
	if len(retOffs) == 0 {
		return nil, fmt.Errorf("no RET offsets resolved (vaddrs=%d)", len(retVAs))
	}
	sort.Slice(retOffs, func(i, j int) bool { return retOffs[i] < retOffs[j] })
	return retOffs, nil
}

func findRetInstsAMD64(code []byte, base uint64) ([]uint64, error) {
	var addrs []uint64
	for off := 0; off < len(code); {
		// Fast-path for RET opcodes (covers near/far, imm16 forms).
		// This keeps the scan resilient if the decoder stumbles on Go codegen.
		if off < len(code) {
			switch code[off] {
			case 0xC3, 0xC2, 0xCB, 0xCA:
				addrs = append(addrs, base+uint64(off))
			}
		}

		inst, err := x86asm.Decode(code[off:], 64)
		if err != nil || inst.Len == 0 {
			// If decode fails, advance by 1 to avoid infinite loops.
			off++
			continue
		}
		if inst.Op == x86asm.RET {
			addrs = append(addrs, base+uint64(off))
		}
		off += inst.Len
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no RET instructions found (amd64)")
	}
	return addrs, nil
}

func findRetInstsARM64(code []byte, base uint64) ([]uint64, error) {
	var addrs []uint64
	// ARM64 instructions are 4 bytes.
	for off := 0; off+4 <= len(code); off += 4 {
		inst, err := arm64asm.Decode(code[off : off+4])
		if err != nil {
			continue
		}
		if inst.Op == arm64asm.RET {
			addrs = append(addrs, base+uint64(off))
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no RET instructions found (arm64)")
	}
	return addrs, nil
}
