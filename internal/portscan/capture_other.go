//go:build !linux

package portscan

import "context"

// StartCapture is a no-op off Linux: raw packet capture there means an external
// dependency (Npcap on Windows) or a different API (BPF devices on the BSDs),
// either of which would cost the single-static-binary property the fan-out
// detector exists to preserve. The event feeder is the whole detector here.
func (d *Detector) StartCapture(ctx context.Context, tcp, udp map[int]bool, logf func(string, ...any)) {
	logf("portscan: packet-level detection is Linux-only; running fan-out detection only")
}
