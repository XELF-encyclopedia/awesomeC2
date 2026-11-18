package bdc2

// NOTICE demultiplexing for the merged client (see fact #4849).
//
// BDC2 v1 has no dedicated tunnel frame type and the frame layout is frozen.
// Advanced client modules therefore post asynchronous tunnel events inside a
// NOTICE (type 12) frame as TLV:
//
//	sub   = "tunnel"
//	ftype = decimal type (0x41 = data, 0x42 = close)
//	data  = 4-byte big-endian tunnel id || payload   (payload empty for close)
//
// Operators must demultiplex these by "sub" instead of treating the NOTICE as
// end-of-RPC or as ordinary task output. The server keeps ignoring client
// NOTICE frames (unchanged), so this parser is what lets a future/relayed
// NOTICE arrive without breaking request/response handling.

import (
	"encoding/binary"
	"strconv"
)

const (
	// TunnelFTypeData carries tunnel payload bytes after the 4-byte id.
	TunnelFTypeData uint8 = 0x41
	// TunnelFTypeClose announces that the tunnel id was closed.
	TunnelFTypeClose uint8 = 0x42
)

// TunnelNotice is a decoded NOTICE(sub=tunnel) event.
type TunnelNotice struct {
	FType uint8
	TID   uint32
	Data  []byte
}

func (t TunnelNotice) IsData() bool  { return t.FType == TunnelFTypeData }
func (t TunnelNotice) IsClose() bool { return t.FType == TunnelFTypeClose }

// ParseTunnelNotice returns the tunnel event carried by a NOTICE TLV map, and
// reports whether the NOTICE was a tunnel notice at all.
func ParseTunnelNotice(kv map[string][]byte) (TunnelNotice, bool) {
	if string(kv["sub"]) != "tunnel" {
		return TunnelNotice{}, false
	}
	f, _ := strconv.ParseUint(string(kv["ftype"]), 10, 8)
	raw := kv["data"]
	var tn TunnelNotice
	tn.FType = uint8(f)
	if len(raw) >= 4 {
		tn.TID = binary.BigEndian.Uint32(raw[:4])
		tn.Data = raw[4:]
	} else {
		tn.Data = raw
	}
	return tn, true
}

// TunnelNoticeFrame builds the TLV map for a NOTICE(sub=tunnel) event. It is
// used by tests and by any Go-side tooling that synthesises tunnel notices; it
// does not add a new frame type.
func TunnelNoticeFrame(ftype uint8, tid uint32, payload []byte) map[string][]byte {
	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], tid)
	copy(data[4:], payload)
	return map[string][]byte{
		"sub":   []byte("tunnel"),
		"ftype": []byte(strconv.Itoa(int(ftype))),
		"data":  data,
	}
}
