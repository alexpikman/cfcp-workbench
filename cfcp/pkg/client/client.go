package client

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/cfcp/protocol/pkg/crypto"
	"github.com/cfcp/protocol/pkg/protocol"
)

// NetworkSimulationConfig allows injecting artificial faults for testing.
type NetworkSimulationConfig struct {
	PacketLossPercent int           // 0-100% chance to drop fragment
	DuplicatePercent  int           // 0-100% chance to send duplicate fragment
	MaxJitterDelay    time.Duration // random delay before transmission (triggers reordering)
	ShuffleFragments  bool          // shuffle sending order to test out-of-order cascade
}

// ClientConfig holds configuration for the CFCP client.
type ClientConfig struct {
	ServerAddr  string
	PSK         []byte
	FragmentMTU int           // Payload bytes per fragment (e.g. 1024)
	ACKTimeout  time.Duration // Time to wait for ACK
	SimConfig   NetworkSimulationConfig
}

// ClientStats records client-side telemetry.
type ClientStats struct {
	MessagesSent     uint64        `json:"messages_sent"`
	FragmentsSent    uint64        `json:"fragments_sent"`
	SimulatedDrops   uint64        `json:"simulated_drops"`
	DuplicatesSent   uint64        `json:"duplicates_sent"`
	ACKsReceived     uint64        `json:"acks_received"`
	Retransmissions  uint64        `json:"retransmissions"`
	LastRTT          time.Duration `json:"last_rtt"`
	TotalBytesSent   uint64        `json:"total_bytes_sent"`
}

// Client is a CFCP UDP client.
type Client struct {
	config ClientConfig
	cipher *crypto.AEADCipher
	conn   *net.UDPConn
	mu     sync.Mutex
	stats  ClientStats
}

// NewClient initializes a new CFCP client.
func NewClient(cfg ClientConfig) (*Client, error) {
	cipher, err := crypto.NewAEADCipher(cfg.PSK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AEAD cipher: %w", err)
	}

	if cfg.FragmentMTU <= 0 {
		cfg.FragmentMTU = 1024
	}
	if cfg.ACKTimeout <= 0 {
		cfg.ACKTimeout = 4 * time.Second
	}

	return &Client{
		config: cfg,
		cipher: cipher,
	}, nil
}

// Connect opens the UDP socket.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	raddr, err := net.ResolveUDPAddr("udp", c.config.ServerAddr)
	if err != nil {
		return fmt.Errorf("resolve server address error: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("dial UDP error: %w", err)
	}

	c.conn = conn
	return nil
}

// Close closes the UDP socket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// SendMessage slices, encrypts, and transmits a payload across the cascade.
func (c *Client) SendMessage(payload []byte) (uint64, time.Duration, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return 0, 0, err
		}
	}

	startTime := time.Now()

	// 1. Generate unique 64-bit Message ID
	msgID := generateMessageID()

	// 2. Compute SHA-256 whole-message integrity digest
	messageDigest := crypto.ComputeMessageDigest(payload)

	// 3. Slice message into MTU-sized chunks
	chunkSize := c.config.FragmentMTU
	totalLen := len(payload)
	totalFragments := (totalLen + chunkSize - 1) / chunkSize
	if totalFragments == 0 {
		totalFragments = 1
	}

	packets := make([]*protocol.Packet, totalFragments)
	for i := 0; i < totalFragments; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > totalLen {
			end = totalLen
		}
		chunk := payload[start:end]

		// Color cascade tag (cycle through colors)
		color := protocol.ColorTag(i % 7)

		// Create provisional packet for AAD computation
		pkt := &protocol.Packet{
			Version:        protocol.ProtocolVersion,
			Flags:          protocol.FlagData | protocol.FlagEncrypted,
			Color:          color,
			MessageID:      msgID,
			FragmentIndex:  uint32(i),
			TotalFragments: uint32(totalFragments),
			MessageDigest:  messageDigest,
		}

		// Encrypt fragment with ChaCha20-Poly1305 using header AAD
		aad := pkt.HeaderAAD()
		ciphertext := c.cipher.EncryptFragment(msgID, uint32(i), chunk, aad)
		pkt.Payload = ciphertext
		pkt.PayloadLength = uint32(len(ciphertext))

		packets[i] = pkt
	}

	// 4. Transmission (with optional fault injection & out-of-order cascade)
	sendOrder := make([]int, totalFragments)
	for i := range sendOrder {
		sendOrder[i] = i
	}

	if c.config.SimConfig.ShuffleFragments && totalFragments > 1 {
		// Fisher-Yates shuffle
		for i := len(sendOrder) - 1; i > 0; i-- {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
			j := int(nBig.Int64())
			sendOrder[i], sendOrder[j] = sendOrder[j], sendOrder[i]
		}
	}

	// Send fragments
	for _, idx := range sendOrder {
		pkt := packets[idx]

		// Fault simulation: Packet loss
		if c.config.SimConfig.PacketLossPercent > 0 {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(100))
			if int(nBig.Int64()) < c.config.SimConfig.PacketLossPercent {
				c.mu.Lock()
				c.stats.SimulatedDrops++
				c.mu.Unlock()
				continue // Drop packet
			}
		}

		// Fault simulation: Jitter
		if c.config.SimConfig.MaxJitterDelay > 0 {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(c.config.SimConfig.MaxJitterDelay)))
			time.Sleep(time.Duration(nBig.Int64()))
		}

		wireBytes, err := pkt.MarshalBinary()
		if err != nil {
			return msgID, 0, fmt.Errorf("marshal fragment error: %w", err)
		}

		if _, err := c.conn.Write(wireBytes); err != nil {
			return msgID, 0, fmt.Errorf("send fragment error: %w", err)
		}

		c.mu.Lock()
		c.stats.FragmentsSent++
		c.stats.TotalBytesSent += uint64(len(wireBytes))
		c.mu.Unlock()

		// Fault simulation: Duplicate packet
		if c.config.SimConfig.DuplicatePercent > 0 {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(100))
			if int(nBig.Int64()) < c.config.SimConfig.DuplicatePercent {
				c.conn.Write(wireBytes)
				c.mu.Lock()
				c.stats.DuplicatesSent++
				c.stats.FragmentsSent++
				c.mu.Unlock()
			}
		}
	}

	// 5. Wait for ACK with timeout
	c.conn.SetReadDeadline(time.Now().Add(c.config.ACKTimeout))
	ackBuf := make([]byte, 1024)
	n, err := c.conn.Read(ackBuf)
	if err != nil {
		return msgID, 0, fmt.Errorf("awaiting ACK timeout or error: %w", err)
	}

	ackPkt, err := protocol.UnmarshalBinary(ackBuf[:n])
	if err != nil {
		return msgID, 0, fmt.Errorf("unmarshal ACK packet error: %w", err)
	}

	if ackPkt.MessageID != msgID || (ackPkt.Flags&protocol.FlagACK == 0) {
		return msgID, 0, errors.New("received invalid or mismatched ACK")
	}

	rtt := time.Since(startTime)

	c.mu.Lock()
	c.stats.MessagesSent++
	c.stats.ACKsReceived++
	c.stats.LastRTT = rtt
	c.mu.Unlock()

	return msgID, rtt, nil
}

// GetStats returns client telemetry.
func (c *Client) GetStats() ClientStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func generateMessageID() uint64 {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return binary.BigEndian.Uint64(b)
}
