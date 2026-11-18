package protocol

import (
	"encoding/json"
	"fmt"
)

// DefaultFragSize is the plaintext chunk size used when a transport has a
// small MTU (UDP/DNS/DoH).
const DefaultFragSize = 700

// FragmentJSON splits a plaintext JSON message into frag envelopes. If the
// payload fits, it is returned unchanged as a single item.
func FragmentJSON(plain []byte, max int, fid string) ([][]byte, error) {
	if max <= 0 {
		max = DefaultFragSize
	}
	if len(plain) <= max {
		return [][]byte{plain}, nil
	}
	total := (len(plain) + max - 1) / max
	out := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		lo := i * max
		hi := lo + max
		if hi > len(plain) {
			hi = len(plain)
		}
		f := Frag{T: TFrag, FID: fid, Idx: i, Total: total, Data: B64(plain[lo:hi])}
		b, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// Reassembler rebuilds messages from Frag parts.
type Reassembler struct {
	parts map[string][][]byte
	total map[string]int
}

func NewReassembler() *Reassembler {
	return &Reassembler{parts: map[string][][]byte{}, total: map[string]int{}}
}

// Add consumes a Frag message; returns the reassembled payload when complete.
func (r *Reassembler) Add(f *Frag) ([]byte, bool, error) {
	if f.Total <= 0 || f.Total > 100000 {
		return nil, false, fmt.Errorf("bad frag total %d", f.Total)
	}
	if f.Idx < 0 || f.Idx >= f.Total {
		return nil, false, fmt.Errorf("bad frag index %d", f.Idx)
	}
	if _, ok := r.parts[f.FID]; !ok {
		r.parts[f.FID] = make([][]byte, f.Total)
		r.total[f.FID] = f.Total
	}
	if r.total[f.FID] != f.Total {
		return nil, false, fmt.Errorf("frag total mismatch for %s", f.FID)
	}
	chunk, err := DecodeB64(f.Data)
	if err != nil {
		return nil, false, err
	}
	r.parts[f.FID][f.Idx] = chunk
	for _, p := range r.parts[f.FID] {
		if p == nil {
			return nil, false, nil
		}
	}
	var out []byte
	for _, p := range r.parts[f.FID] {
		out = append(out, p...)
	}
	delete(r.parts, f.FID)
	delete(r.total, f.FID)
	return out, true, nil
}
