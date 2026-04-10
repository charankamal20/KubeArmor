// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package events

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

// Must match struct go_h2_transport_event in commonstructs.h.
const (
    GoH2MaxFields = 8
    GoH2NameSize  = 32
    GoH2ValSize   = 128
)

// GoH2HdrField mirrors struct go_h2_hdr_field.
type GoH2HdrField struct {
    Name  [GoH2NameSize]byte
    Value [GoH2ValSize]byte
}

// GoH2TransportEvent mirrors struct go_h2_transport_event.
// Total size: 4+4+1+1+2 + 8*(32+128) = 8 + 1280 = 1288 bytes.
type GoH2TransportEvent struct {
    PID        uint32
    StreamID   uint32
    IsServer   uint8
    FieldCount uint8
    Pad        uint16
    Fields     [GoH2MaxFields]GoH2HdrField
}

const goH2TransportEventSize = 4 + 4 + 1 + 1 + 2 + GoH2MaxFields*(GoH2NameSize+GoH2ValSize)

// ParseGoH2TransportEvent decodes a raw ring-buffer sample into a GoH2TransportEvent.
func ParseGoH2TransportEvent(raw []byte) (*GoH2TransportEvent, error) {
    if len(raw) < goH2TransportEventSize {
        return nil, fmt.Errorf("go_h2_transport_event: short read %d < %d", len(raw), goH2TransportEventSize)
    }
    ev := &GoH2TransportEvent{}
    if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
        return nil, fmt.Errorf("go_h2_transport_event decode: %w", err)
    }
    return ev, nil
}

// Headers returns a map[string]string of the decoded header fields, trimming NUL bytes.
func (e *GoH2TransportEvent) Headers() map[string]string {
    out := make(map[string]string, int(e.FieldCount))
    // Iterate all slots — BPF writes at index i (loop variable),
    // so there may be gaps from skipped fields. FieldCount is only
    // a hint for the map pre-allocation.
    for i := range GoH2MaxFields {
        name := cString(e.Fields[i].Name[:])
        if name == "" {
            continue // skipped slot
        }
        out[name] = cString(e.Fields[i].Value[:])
    }
    return out
}

// cString converts a NUL-terminated byte slice to a Go string.
func cString(b []byte) string {
    if before, _, ok := bytes.Cut(b, []byte{0}); ok {
        return string(before)
    }
    return string(b)
}
