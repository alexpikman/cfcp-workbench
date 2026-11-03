package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfcp/protocol/pkg/assembler"
	"github.com/cfcp/protocol/pkg/crypto"
	"github.com/cfcp/protocol/pkg/protocol"
)

// ServerConfig holds UDP server settings.
type ServerConfig struct {
	ListenAddr      string
	PSK             []byte
	AssemblerConfig assembler.AssemblerConfig
}

// ServerStats collects operational metrics.
type ServerStats struct {
	PacketsReceived  uint64 `json:"packets_received"`
	ACKsSent         uint64 `json:"acks_sent"`
	CorruptedPackets uint64 `json:"corrupted_packets"`
	BytesReceived    uint64 `json:"bytes_received"`
}

// Server represents a CFCP UDP server.
type Server struct {
	config    ServerConfig
	cipher    *crypto.AEADCipher
	assembler *assembler.MessageAssembler
	conn      *net.UDPConn
	stopChan  chan struct{}
	wg        sync.WaitGroup

	stats      ServerStats
	mu         sync.RWMutex
	onMessage  func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr)
}

// NewServer initializes a new CFCP UDP server.
func NewServer(cfg ServerConfig) (*Server, error) {
	cipher, err := crypto.NewAEADCipher(cfg.PSK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AEAD cipher: %w", err)
	}

	ma := assembler.NewMessageAssembler(cfg.AssemblerConfig, cipher)

	return &Server{
		config:    cfg,
		cipher:    cipher,
		assembler: ma,
		stopChan:  make(chan struct{}),
	}, nil
}

// OnMessage sets the handler for fully assembled, verified messages.
func (s *Server) OnMessage(fn func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onMessage = fn
}

// Start opens the UDP listener and starts processing incoming datagrams.
func (s *Server) Start() error {
	laddr, err := net.ResolveUDPAddr("udp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP listen addr error: %w", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen UDP error: %w", err)
	}

	s.conn = conn
	s.wg.Add(1)
	go s.listenLoop()

	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	close(s.stopChan)
	if s.conn != nil {
		s.conn.Close()
	}
	s.assembler.Close()
	s.wg.Wait()
	return nil
}

// listenLoop continuously reads incoming datagrams from the UDP socket.
func (s *Server) listenLoop() {
	defer s.wg.Done()
	buffer := make([]byte, 65535)

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			select {
			case <-s.stopChan:
				return
			default:
				continue
			}
		}

		atomic.AddUint64(&s.stats.PacketsReceived, 1)
		atomic.AddUint64(&s.stats.BytesReceived, uint64(n))

		// Parse binary packet
		pkt, err := protocol.UnmarshalBinary(buffer[:n])
		if err != nil {
			atomic.AddUint64(&s.stats.CorruptedPackets, 1)
			continue
		}

		// Feed to assembler
		completed, err := s.assembler.ProcessPacket(pkt)
		if err != nil {
			// Expected during duplicate or corrupted fragments
			continue
		}

		// If message is complete and verified
		if completed != nil {
			// Send ACK back to client
			s.sendACK(completed.MessageID, remoteAddr)

			s.mu.RLock()
			cb := s.onMessage
			s.mu.RUnlock()

			if cb != nil {
				cb(completed, remoteAddr)
			}
		}
	}
}

// sendACK creates and sends a CFCP ACK packet to the client.
func (s *Server) sendACK(messageID uint64, remoteAddr *net.UDPAddr) {
	ackPkt := &protocol.Packet{
		Version:        protocol.ProtocolVersion,
		Flags:          protocol.FlagACK,
		Color:          protocol.ColorWhite,
		MessageID:      messageID,
		FragmentIndex:  0,
		TotalFragments: 1,
	}

	wireBytes, err := ackPkt.MarshalBinary()
	if err != nil {
		return
	}

	_, _ = s.conn.WriteToUDP(wireBytes, remoteAddr)
	atomic.AddUint64(&s.stats.ACKsSent, 1)
}

// GetStats returns server metrics.
func (s *Server) GetStats() (ServerStats, assembler.AssemblerStats) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats, s.assembler.GetStats()
}

// GetAssembler returns the internal MessageAssembler for inspection.
func (s *Server) GetAssembler() *assembler.MessageAssembler {
	return s.assembler
}
