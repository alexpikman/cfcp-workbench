package porthopper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cfcp/protocol/pkg/protocol"
)

// Mode defines the port strategy.
type Mode string

const (
	ModeDynamicHopping Mode = "dynamic_hopping" // Pseudo-random synchronized port hopping
	ModeColorSprayed   Mode = "color_sprayed"   // Different port per cascade color tag
	ModeMasqueradeQUIC Mode = "masquerade_quic" // Port 443 (QUIC / HTTP3 camouflage)
	ModeMasqueradeWebRTC Mode = "masquerade_webrtc" // Port 3478 (STUN/TURN video camouflage)
	ModeFixedPort      Mode = "fixed_port"      // Single default port
)

// Config holds parameters for port hopping and anti-tracking defense.
type Config struct {
	Mode           Mode
	PSK            []byte        // Shared secret for deterministic PRNG hopping
	MinPort        int           // Lower bound (e.g. 25000)
	MaxPort        int           // Upper bound (e.g. 35000)
	DefaultPort    int           // Fallback port (e.g. 9099)
	WindowDuration time.Duration // Interval before hopping to next port (e.g. 10s)
}

// DefaultConfig returns recommended settings for DPI evasion.
func DefaultConfig(psk []byte) Config {
	return Config{
		Mode:           ModeDynamicHopping,
		PSK:            psk,
		MinPort:        20000,
		MaxPort:        40000,
		DefaultPort:    9099,
		WindowDuration: 5 * time.Second,
	}
}

// PortHopper calculates deterministic port numbers synchronized between client and server.
type PortHopper struct {
	config Config
}

// NewPortHopper constructs a hopper instance.
func NewPortHopper(cfg Config) (*PortHopper, error) {
	if cfg.MinPort <= 0 || cfg.MaxPort <= cfg.MinPort || cfg.MaxPort > 65535 {
		return nil, fmt.Errorf("invalid port range [%d - %d]", cfg.MinPort, cfg.MaxPort)
	}
	if len(cfg.PSK) == 0 {
		return nil, fmt.Errorf("PSK required for cryptographic port hopping")
	}
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 5 * time.Second
	}
	return &PortHopper{config: cfg}, nil
}

// GetPort calculates the target UDP port for a specific time and fragment color.
func (h *PortHopper) GetPort(t time.Time, color protocol.ColorTag) int {
	switch h.config.Mode {
	case ModeMasqueradeQUIC:
		return 443
	case ModeMasqueradeWebRTC:
		return 3478
	case ModeFixedPort:
		return h.config.DefaultPort
	case ModeColorSprayed:
		// Base hop on window + color tag
		window := t.Unix() / int64(h.config.WindowDuration.Seconds())
		return h.derivePort(window, uint32(color))
	case ModeDynamicHopping:
		fallthrough
	default:
		window := t.Unix() / int64(h.config.WindowDuration.Seconds())
		return h.derivePort(window, 0)
	}
}

// GetListeningPorts returns all ports the server should bind to for the current configuration.
func (h *PortHopper) GetListeningPorts(t time.Time) []int {
	switch h.config.Mode {
	case ModeMasqueradeQUIC:
		return []int{443}
	case ModeMasqueradeWebRTC:
		return []int{3478}
	case ModeFixedPort:
		return []int{h.config.DefaultPort}
	case ModeColorSprayed:
		// Returns active ports across all 8 cascade colors + adjacent time windows to prevent race conditions
		window := t.Unix() / int64(h.config.WindowDuration.Seconds())
		portMap := make(map[int]struct{})
		for _, w := range []int64{window - 1, window, window + 1} {
			for c := protocol.ColorRed; c <= protocol.ColorWhite; c++ {
				portMap[h.derivePort(w, uint32(c))] = struct{}{}
			}
		}
		ports := make([]int, 0, len(portMap))
		for p := range portMap {
			ports = append(ports, p)
		}
		return ports
	case ModeDynamicHopping:
		fallthrough
	default:
		// Listen on current, previous, and next time windows (handles clock skew)
		window := t.Unix() / int64(h.config.WindowDuration.Seconds())
		portMap := make(map[int]struct{})
		for _, w := range []int64{window - 1, window, window + 1} {
			portMap[h.derivePort(w, 0)] = struct{}{}
		}
		ports := make([]int, 0, len(portMap))
		for p := range portMap {
			ports = append(ports, p)
		}
		return ports
	}
}

// derivePort derives an HMAC-based port number in [MinPort, MaxPort].
func (h *PortHopper) derivePort(window int64, discriminator uint32) int {
	mac := hmac.New(sha256.New, h.config.PSK)
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[0:8], uint64(window))
	binary.BigEndian.PutUint32(b[8:12], discriminator)
	mac.Write(b)
	digest := mac.Sum(nil)

	// Convert first 4 bytes of hash to uint32
	val := binary.BigEndian.Uint32(digest[0:4])
	portSpan := uint32(h.config.MaxPort - h.config.MinPort + 1)
	offset := val % portSpan
	return h.config.MinPort + int(offset)
}
