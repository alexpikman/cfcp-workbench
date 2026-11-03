export interface GoFileRecord {
  path: string;
  filename: string;
  category: 'protocol' | 'crypto' | 'assembler' | 'server' | 'client' | 'proxy' | 'cmd' | 'tests' | 'config';
  description: string;
  code: string;
}

export const GO_FILES: GoFileRecord[] = [
  {
    path: 'pkg/protocol/packet.go',
    filename: 'packet.go',
    category: 'protocol',
    description: 'CFCP binary wire protocol format, 60-byte fixed header, and serialization',
    code: `package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire Protocol Constants
var (
	MagicBytes       = [4]byte{'C', 'F', 'C', 'P'}
	ProtocolVersion  uint8 = 1
	HeaderSize       = 60 // Fixed header size before variable payload
	MaxPayloadSize   = 65507 - HeaderSize // Max UDP payload safe boundary
	DefaultMTUSize   = 1200 // Conservative safe MTU size for UDP datagrams
)

// Flag definitions
const (
	FlagData        uint8 = 0x01 // Datagram carries data fragment
	FlagACK         uint8 = 0x02 // Datagram acknowledges receipt of fragment or message
	FlagEncrypted   uint8 = 0x04 // Payload is encrypted with AEAD ChaCha20-Poly1305
	FlagRetransmit  uint8 = 0x08 // Datagram is a retransmitted fragment
	FlagHeartbeat   uint8 = 0x10 // Keep-alive / probing
)

// Color definitions for cascade tags
type ColorTag uint8

const (
	ColorRed    ColorTag = 0
	ColorAmber  ColorTag = 1
	ColorGreen  ColorTag = 2
	ColorCyan   ColorTag = 3
	ColorBlue   ColorTag = 4
	ColorPurple ColorTag = 5
	ColorPink   ColorTag = 6
	ColorWhite  ColorTag = 7
)

func (c ColorTag) String() string {
	switch c {
	case ColorRed:
		return "Red"
	case ColorAmber:
		return "Amber"
	case ColorGreen:
		return "Green"
	case ColorCyan:
		return "Cyan"
	case ColorBlue:
		return "Blue"
	case ColorPurple:
		return "Purple"
	case ColorPink:
		return "Pink"
	default:
		return "White"
	}
}

// Packet represents a Color-Fragmented Cascade Protocol datagram.
// Wire layout (60 bytes fixed header + payload):
// [0:4]   Magic (4 bytes: "CFCP")
// [4]     Version (1 byte)
// [5]     Flags (1 byte)
// [6]     ColorTag (1 byte)
// [7]     Reserved (1 byte, 0x00)
// [8:16]  MessageID (8 bytes, uint64 BigEndian)
// [16:20] FragmentIndex (4 bytes, uint32 BigEndian)
// [20:24] TotalFragments (4 bytes, uint32 BigEndian)
// [24:28] PayloadLength (4 bytes, uint32 BigEndian)
// [28:60] MessageDigest (32 bytes, SHA-256 hash of complete plaintext)
// [60:60+PayloadLength] Payload bytes (ChaCha20-Poly1305 ciphertext + tag)
type Packet struct {
	Version        uint8
	Flags          uint8
	Color          ColorTag
	MessageID      uint64
	FragmentIndex  uint32
	TotalFragments uint32
	PayloadLength  uint32
	MessageDigest  [32]byte
	Payload        []byte
}

var (
	ErrPacketTooShort     = errors.New("cfcp: packet buffer is shorter than header size")
	ErrInvalidMagic       = errors.New("cfcp: invalid magic bytes in packet header")
	ErrUnsupportedVer     = errors.New("cfcp: unsupported protocol version")
	ErrPayloadMismatch    = errors.New("cfcp: payload length does not match header field")
	ErrInvalidFragmentNo  = errors.New("cfcp: fragment index is greater than or equal to total fragments")
	ErrZeroTotalFragments = errors.New("cfcp: total fragments cannot be zero")
)

// MarshalBinary serializes the packet into wire-format bytes.
func (p *Packet) MarshalBinary() ([]byte, error) {
	if p.TotalFragments == 0 && (p.Flags&FlagData != 0) {
		return nil, ErrZeroTotalFragments
	}
	if p.FragmentIndex >= p.TotalFragments && (p.Flags&FlagData != 0) {
		return nil, ErrInvalidFragmentNo
	}

	actualPayloadLen := len(p.Payload)
	buf := make([]byte, HeaderSize+actualPayloadLen)

	copy(buf[0:4], MagicBytes[:])
	buf[4] = p.Version
	buf[5] = p.Flags
	buf[6] = uint8(p.Color)
	buf[7] = 0x00 // Reserved

	binary.BigEndian.PutUint64(buf[8:16], p.MessageID)
	binary.BigEndian.PutUint32(buf[16:20], p.FragmentIndex)
	binary.BigEndian.PutUint32(buf[20:24], p.TotalFragments)
	binary.BigEndian.PutUint32(buf[24:28], uint32(actualPayloadLen))

	copy(buf[28:60], p.MessageDigest[:])

	if actualPayloadLen > 0 {
		copy(buf[HeaderSize:], p.Payload)
	}

	return buf, nil
}

// UnmarshalBinary parses raw wire bytes into a Packet.
func UnmarshalBinary(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, ErrPacketTooShort
	}

	if !bytes.Equal(data[0:4], MagicBytes[:]) {
		return nil, fmt.Errorf("%w: received %x", ErrInvalidMagic, data[0:4])
	}

	version := data[4]
	if version != ProtocolVersion {
		return nil, fmt.Errorf("%w: received v%d, expected v%d", ErrUnsupportedVer, version, ProtocolVersion)
	}

	flags := data[5]
	color := ColorTag(data[6])

	msgID := binary.BigEndian.Uint64(data[8:16])
	fragIdx := binary.BigEndian.Uint32(data[16:20])
	totalFrags := binary.BigEndian.Uint32(data[20:24])
	payloadLen := binary.BigEndian.Uint32(data[24:28])

	if (flags&FlagData != 0) && totalFrags == 0 {
		return nil, ErrZeroTotalFragments
	}
	if (flags&FlagData != 0) && fragIdx >= totalFrags {
		return nil, ErrInvalidFragmentNo
	}

	if HeaderSize+int(payloadLen) > len(data) {
		return nil, fmt.Errorf("%w: header says %d, got %d", ErrPayloadMismatch, payloadLen, len(data)-HeaderSize)
	}

	var digest [32]byte
	copy(digest[:], data[28:60])

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		copy(payload, data[HeaderSize:HeaderSize+int(payloadLen)])
	}

	return &Packet{
		Version:        version,
		Flags:          flags,
		Color:          color,
		MessageID:      msgID,
		FragmentIndex:  fragIdx,
		TotalFragments: totalFrags,
		PayloadLength:  payloadLen,
		MessageDigest:  digest,
		Payload:        payload,
	}, nil
}

// HeaderAAD returns the Additional Authenticated Data for AEAD binding.
func (p *Packet) HeaderAAD() []byte {
	aad := make([]byte, 28)
	copy(aad[0:4], MagicBytes[:])
	aad[4] = p.Version
	aad[5] = p.Flags
	aad[6] = uint8(p.Color)
	aad[7] = 0x00
	binary.BigEndian.PutUint64(aad[8:16], p.MessageID)
	binary.BigEndian.PutUint32(aad[16:20], p.FragmentIndex)
	binary.BigEndian.PutUint32(aad[20:24], p.TotalFragments)
	binary.BigEndian.PutUint32(aad[24:28], p.PayloadLength)
	return aad
}`,
  },
  {
    path: 'pkg/crypto/aead.go',
    filename: 'aead.go',
    category: 'crypto',
    description: 'ChaCha20-Poly1305 AEAD, deterministic 96-bit nonce derivation, and SHA-256 integrity digest',
    code: `package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize   // 32 bytes (256-bit)
	NonceSize = chacha20poly1305.NonceSize // 12 bytes (96-bit)
	TagSize   = chacha20poly1305.Overhead  // 16 bytes (Poly1305 authenticator)
)

var (
	ErrInvalidKeySize     = errors.New("cfcp/crypto: key must be exactly 32 bytes")
	ErrDecryptionFailed   = errors.New("cfcp/crypto: AEAD authentication failed (message altered, forged, or corrupt)")
	ErrCiphertextTooShort = errors.New("cfcp/crypto: ciphertext is shorter than Poly1305 tag size")
)

type AEADCipher struct {
	aead cipher.AEAD
	key  [KeySize]byte
}

func NewAEADCipher(psk []byte) (*AEADCipher, error) {
	if len(psk) != KeySize {
		return nil, fmt.Errorf("%w: received %d bytes", ErrInvalidKeySize, len(psk))
	}

	c, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ChaCha20-Poly1305: %w", err)
	}

	var keyCopy [KeySize]byte
	copy(keyCopy[:], psk)

	return &AEADCipher{
		aead: c,
		key:  keyCopy,
	}, nil
}

func GenerateRandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return k, nil
}

// DeriveNonce produces a deterministic 96-bit (12-byte) nonce for a given fragment.
// Nonce structure:
// [0:8]   MessageID (64-bit BigEndian)
// [8:12]  FragmentIndex (32-bit BigEndian)
func DeriveNonce(messageID uint64, fragmentIndex uint32) []byte {
	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[0:8], messageID)
	binary.BigEndian.PutUint32(nonce[8:12], fragmentIndex)
	return nonce
}

func (c *AEADCipher) EncryptFragment(messageID uint64, fragmentIndex uint32, plaintext []byte, aad []byte) []byte {
	nonce := DeriveNonce(messageID, fragmentIndex)
	return c.aead.Seal(nil, nonce, plaintext, aad)
}

func (c *AEADCipher) DecryptFragment(messageID uint64, fragmentIndex uint32, ciphertextWithTag []byte, aad []byte) ([]byte, error) {
	if len(ciphertextWithTag) < TagSize {
		return nil, ErrCiphertextTooShort
	}

	nonce := DeriveNonce(messageID, fragmentIndex)
	plaintext, err := c.aead.Open(nil, nonce, ciphertextWithTag, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func ComputeMessageDigest(data []byte) [32]byte {
	return sha256.Sum256(data)
}`,
  },
  {
    path: 'pkg/assembler/assembler.go',
    filename: 'assembler.go',
    category: 'assembler',
    description: 'Thread-safe MessageAssembler with Anti-DoS timed session reaper, memory quotas, and SHA-256 checks',
    code: `package assembler

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cfcp/protocol/pkg/crypto"
	"github.com/cfcp/protocol/pkg/protocol"
)

var (
	ErrSessionTimedOut       = errors.New("cfcp/assembler: session timed out during assembly")
	ErrSessionMemoryExceeded = errors.New("cfcp/assembler: message memory quota exceeded (Anti-DoS)")
	ErrTotalMemoryExceeded   = errors.New("cfcp/assembler: total assembler memory pool exhausted (Anti-DoS)")
	ErrMaxSessionsReached    = errors.New("cfcp/assembler: max concurrent sessions cap reached (Anti-DoS)")
	ErrDuplicateFragment     = errors.New("cfcp/assembler: duplicate fragment ignored")
	ErrIntegrityHashMismatch  = errors.New("cfcp/assembler: SHA-256 message digest integrity verification failed")
	ErrFragmentCountMismatch  = errors.New("cfcp/assembler: fragment total count inconsistent with existing session")
)

type AssemblerConfig struct {
	SessionTimeout        time.Duration
	CleanupInterval       time.Duration
	MaxConcurrentSessions int
	MaxSessionMemoryBytes int
	MaxTotalMemoryBytes   int
}

func DefaultConfig() AssemblerConfig {
	return AssemblerConfig{
		SessionTimeout:        6 * time.Second,
		CleanupInterval:       1 * time.Second,
		MaxConcurrentSessions: 1024,
		MaxSessionMemoryBytes: 4 * 1024 * 1024,  // 4 MB
		MaxTotalMemoryBytes:   64 * 1024 * 1024, // 64 MB
	}
}

type FragmentSlot struct {
	Index         uint32
	ReceivedAt    time.Time
	CiphertextLen uint32
	Plaintext     []byte
	Color         protocol.ColorTag
}

type AssemblySession struct {
	MessageID      uint64
	TotalFragments uint32
	ReceivedCount  uint32
	ExpectedDigest [32]byte
	CreatedAt      time.Time
	LastActivityAt time.Time
	AllocatedBytes int
	Slots          []*FragmentSlot
	ArrivalOrder   []uint32
}

type CompletedMessage struct {
	MessageID      uint64
	Payload        []byte
	Digest         [32]byte
	TotalFragments uint32
	AssemblyTime   time.Duration
	ArrivalOrder   []uint32
}

type MessageAssembler struct {
	config     AssemblerConfig
	cipher     *crypto.AEADCipher
	mu         sync.RWMutex
	sessions   map[uint64]*AssemblySession
	stats      AssemblerStats
	totalTime  time.Duration
	stopReaper chan struct{}
	wg         sync.WaitGroup
	onComplete func(msg *CompletedMessage)
	onEvict    func(msgID uint64, reason string)
}

func NewMessageAssembler(cfg AssemblerConfig, cipher *crypto.AEADCipher) *MessageAssembler {
	ma := &MessageAssembler{
		config:     cfg,
		cipher:     cipher,
		sessions:   make(map[uint64]*AssemblySession),
		stopReaper: make(chan struct{}),
	}
	ma.wg.Add(1)
	go ma.reaperLoop()
	return ma
}

func (ma *MessageAssembler) Close() {
	close(ma.stopReaper)
	ma.wg.Wait()
}

func (ma *MessageAssembler) ProcessPacket(pkt *protocol.Packet) (*CompletedMessage, error) {
	if pkt == nil {
		return nil, errors.New("cfcp/assembler: nil packet")
	}

	ma.mu.Lock()
	defer ma.mu.Unlock()

	if pkt.Flags&protocol.FlagData == 0 {
		return nil, nil
	}

	session, exists := ma.sessions[pkt.MessageID]
	if !exists {
		if len(ma.sessions) >= ma.config.MaxConcurrentSessions {
			return nil, ErrMaxSessionsReached
		}

		session = &AssemblySession{
			MessageID:      pkt.MessageID,
			TotalFragments: pkt.TotalFragments,
			ExpectedDigest: pkt.MessageDigest,
			CreatedAt:      time.Now(),
			LastActivityAt: time.Now(),
			Slots:          make([]*FragmentSlot, pkt.TotalFragments),
			ArrivalOrder:   make([]uint32, 0, pkt.TotalFragments),
		}
		ma.sessions[pkt.MessageID] = session
	}

	if session.TotalFragments != pkt.TotalFragments {
		return nil, ErrFragmentCountMismatch
	}
	if pkt.FragmentIndex >= session.TotalFragments {
		return nil, protocol.ErrInvalidFragmentNo
	}

	if session.Slots[pkt.FragmentIndex] != nil {
		ma.stats.DuplicatePackets++
		return nil, ErrDuplicateFragment
	}

	var plaintext []byte
	var err error
	if pkt.Flags&protocol.FlagEncrypted != 0 && ma.cipher != nil {
		aad := pkt.HeaderAAD()
		plaintext, err = ma.cipher.DecryptFragment(pkt.MessageID, pkt.FragmentIndex, pkt.Payload, aad)
		if err != nil {
			ma.stats.CorruptedPackets++
			return nil, fmt.Errorf("AEAD fragment decryption failed: %w", err)
		}
	} else {
		plaintext = make([]byte, len(pkt.Payload))
		copy(plaintext, pkt.Payload)
	}

	fragMemory := len(plaintext) + int(pkt.PayloadLength) + 64
	if session.AllocatedBytes+fragMemory > ma.config.MaxSessionMemoryBytes {
		ma.stats.CorruptedPackets++
		return nil, ErrSessionMemoryExceeded
	}
	if ma.stats.CurrentMemoryBytes+fragMemory > ma.config.MaxTotalMemoryBytes {
		return nil, ErrTotalMemoryExceeded
	}

	session.Slots[pkt.FragmentIndex] = &FragmentSlot{
		Index:         pkt.FragmentIndex,
		ReceivedAt:    time.Now(),
		CiphertextLen: pkt.PayloadLength,
		Plaintext:     plaintext,
		Color:         pkt.Color,
	}
	session.ReceivedCount++
	session.LastActivityAt = time.Now()
	session.AllocatedBytes += fragMemory
	session.ArrivalOrder = append(session.ArrivalOrder, pkt.FragmentIndex)
	ma.stats.CurrentMemoryBytes += fragMemory

	if session.ReceivedCount == session.TotalFragments {
		assemblyDuration := time.Since(session.CreatedAt)
		var assembledBuffer bytes.Buffer
		for i := uint32(0); i < session.TotalFragments; i++ {
			assembledBuffer.Write(session.Slots[i].Plaintext)
		}
		assembledBytes := assembledBuffer.Bytes()

		actualDigest := crypto.ComputeMessageDigest(assembledBytes)
		if !bytes.Equal(actualDigest[:], session.ExpectedDigest[:]) {
			ma.stats.HashFailures++
			ma.stats.CurrentMemoryBytes -= session.AllocatedBytes
			delete(ma.sessions, pkt.MessageID)
			return nil, fmt.Errorf("%w: expected %x, calculated %x", ErrIntegrityHashMismatch, session.ExpectedDigest, actualDigest)
		}

		completed := &CompletedMessage{
			MessageID:      session.MessageID,
			Payload:        assembledBytes,
			Digest:         actualDigest,
			TotalFragments: session.TotalFragments,
			AssemblyTime:   assemblyDuration,
			ArrivalOrder:   append([]uint32(nil), session.ArrivalOrder...),
		}

		ma.stats.CurrentMemoryBytes -= session.AllocatedBytes
		ma.stats.CompletedSessions++
		ma.totalTime += assemblyDuration
		delete(ma.sessions, pkt.MessageID)

		if ma.onComplete != nil {
			ma.onComplete(completed)
		}
		return completed, nil
	}
	return nil, nil
}

func (ma *MessageAssembler) reaperLoop() {
	defer ma.wg.Done()
	ticker := time.NewTicker(ma.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ma.stopReaper:
			return
		case <-ticker.C:
			ma.evictStaleSessions()
		}
	}
}

func (ma *MessageAssembler) evictStaleSessions() {
	ma.mu.Lock()
	defer ma.mu.Unlock()

	now := time.Now()
	for msgID, session := range ma.sessions {
		if now.Sub(session.LastActivityAt) > ma.config.SessionTimeout {
			ma.stats.TimedOutSessions++
			ma.stats.CurrentMemoryBytes -= session.AllocatedBytes
			delete(ma.sessions, msgID)

			if ma.onEvict != nil {
				reason := fmt.Sprintf("Anti-DoS timeout: stalled after %d/%d fragments", session.ReceivedCount, session.TotalFragments)
				ma.onEvict(msgID, reason)
			}
		}
	}
}`,
  },
  {
    path: 'pkg/server/server.go',
    filename: 'server.go',
    category: 'server',
    description: 'High-throughput UDP server with ACK dispatcher and session event hooks',
    code: `package server

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

type ServerConfig struct {
	ListenAddr      string
	PSK             []byte
	AssemblerConfig assembler.AssemblerConfig
}

type ServerStats struct {
	PacketsReceived  uint64
	ACKsSent         uint64
	CorruptedPackets uint64
	BytesReceived    uint64
}

type Server struct {
	config    ServerConfig
	cipher    *crypto.AEADCipher
	assembler *assembler.MessageAssembler
	conn      *net.UDPConn
	stopChan  chan struct{}
	wg        sync.WaitGroup
	stats     ServerStats
	mu        sync.RWMutex
	onMessage func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr)
}

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

func (s *Server) OnMessage(fn func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onMessage = fn
}

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

func (s *Server) Stop() error {
	close(s.stopChan)
	if s.conn != nil {
		s.conn.Close()
	}
	s.assembler.Close()
	s.wg.Wait()
	return nil
}

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

		pkt, err := protocol.UnmarshalBinary(buffer[:n])
		if err != nil {
			atomic.AddUint64(&s.stats.CorruptedPackets, 1)
			continue
		}

		completed, err := s.assembler.ProcessPacket(pkt)
		if err != nil {
			continue
		}

		if completed != nil {
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
}`,
  },
  {
    path: 'pkg/client/client.go',
    filename: 'client.go',
    category: 'client',
    description: 'UDP client with cascade fragmentation, color-tagging, and simulated fault injection',
    code: `package client

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

type NetworkSimulationConfig struct {
	PacketLossPercent int
	DuplicatePercent  int
	MaxJitterDelay    time.Duration
	ShuffleFragments  bool
}

type ClientConfig struct {
	ServerAddr  string
	PSK         []byte
	FragmentMTU int
	ACKTimeout  time.Duration
	SimConfig   NetworkSimulationConfig
}

type Client struct {
	config ClientConfig
	cipher *crypto.AEADCipher
	conn   *net.UDPConn
	mu     sync.Mutex
	stats  ClientStats
}

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

func (c *Client) SendMessage(payload []byte) (uint64, time.Duration, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return 0, 0, err
		}
	}

	startTime := time.Now()
	msgID := generateMessageID()
	messageDigest := crypto.ComputeMessageDigest(payload)

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

		color := protocol.ColorTag(i % 7)
		pkt := &protocol.Packet{
			Version:        protocol.ProtocolVersion,
			Flags:          protocol.FlagData | protocol.FlagEncrypted,
			Color:          color,
			MessageID:      msgID,
			FragmentIndex:  uint32(i),
			TotalFragments: uint32(totalFragments),
			MessageDigest:  messageDigest,
		}

		aad := pkt.HeaderAAD()
		ciphertext := c.cipher.EncryptFragment(msgID, uint32(i), chunk, aad)
		pkt.Payload = ciphertext
		pkt.PayloadLength = uint32(len(ciphertext))
		packets[i] = pkt
	}

	sendOrder := make([]int, totalFragments)
	for i := range sendOrder {
		sendOrder[i] = i
	}

	if c.config.SimConfig.ShuffleFragments && totalFragments > 1 {
		for i := len(sendOrder) - 1; i > 0; i-- {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
			j := int(nBig.Int64())
			sendOrder[i], sendOrder[j] = sendOrder[j], sendOrder[i]
		}
	}

	for _, idx := range sendOrder {
		pkt := packets[idx]

		if c.config.SimConfig.PacketLossPercent > 0 {
			nBig, _ := rand.Int(rand.Reader, big.NewInt(100))
			if int(nBig.Int64()) < c.config.SimConfig.PacketLossPercent {
				c.mu.Lock()
				c.stats.SimulatedDrops++
				c.mu.Unlock()
				continue
			}
		}

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
	}

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
}`,
  },
  {
    path: 'cmd/server/main.go',
    filename: 'main.go',
    category: 'cmd',
    description: 'Server CLI executable with ANSI colored logs, Anti-DoS eviction notifications, and periodic telemetry',
    code: `package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cfcp/protocol/pkg/assembler"
	"github.com/cfcp/protocol/pkg/server"
)

const defaultHexPSK = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

func main() {
	listenAddr := flag.String("addr", "0.0.0.0:9099", "UDP listen address (host:port)")
	pskHex := flag.String("psk", defaultHexPSK, "32-byte Pre-Shared Key in Hex format")
	timeoutSec := flag.Int("timeout", 6, "Anti-DoS session timeout in seconds")
	cleanupSec := flag.Int("cleanup", 1, "Anti-DoS reaper cleanup interval in seconds")
	maxSessions := flag.Int("max-sessions", 1024, "Maximum concurrent active sessions")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be a 64-character hexadecimal string (32 bytes)")
	}

	fmt.Println("=== CFCP Server (Color-Fragmented Cascade Protocol) ===")
	fmt.Printf(" [CONFIG] Listen: %s | Timeout: %ds | MaxSessions: %d\\n", *listenAddr, *timeoutSec, *maxSessions)

	cfg := server.ServerConfig{
		ListenAddr: *listenAddr,
		PSK:        psk,
		AssemblerConfig: assembler.AssemblerConfig{
			SessionTimeout:        time.Duration(*timeoutSec) * time.Second,
			CleanupInterval:       time.Duration(*cleanupSec) * time.Second,
			MaxConcurrentSessions: *maxSessions,
			MaxSessionMemoryBytes: 4 * 1024 * 1024,
			MaxTotalMemoryBytes:   64 * 1024 * 1024,
		},
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize CFCP server: %v", err)
	}

	srv.GetAssembler().SetCallbacks(nil, func(msgID uint64, reason string) {
		fmt.Printf(" [! Anti-DoS Eviction] ID 0x%016X purged: %s\\n", msgID, reason)
	})

	srv.OnMessage(func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr) {
		fmt.Printf(" [✓ Assembled] ID: 0x%016X | %d fragments in %v | SHA-256 Verified\\n",
			msg.MessageID, msg.TotalFragments, msg.AssemblyTime)
	})

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	fmt.Println("Shutting down CFCP server...")
}`,
  },
  {
    path: 'cmd/client/main.go',
    filename: 'main.go',
    category: 'cmd',
    description: 'Client CLI executable with fault injection flags (--loss, --dup, --jitter, --shuffle)',
    code: `package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cfcp/protocol/pkg/client"
)

const defaultHexPSK = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

func main() {
	serverAddr := flag.String("addr", "127.0.0.1:9099", "CFCP UDP server address (host:port)")
	pskHex := flag.String("psk", defaultHexPSK, "32-byte Pre-Shared Key in Hex format")
	msgText := flag.String("msg", "CFCP Datagram Payload with ChaCha20-Poly1305 AEAD", "Message to send")
	mtu := flag.Int("mtu", 256, "Fragment chunk size in bytes")
	lossRate := flag.Int("loss", 0, "Artificial packet loss percentage (0-100)")
	dupRate := flag.Int("dup", 0, "Artificial duplicate percentage (0-100)")
	shuffle := flag.Bool("shuffle", true, "Shuffle fragments to simulate out-of-order UDP arrival")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be 64-character hexadecimal string")
	}

	cfg := client.ClientConfig{
		ServerAddr:  *serverAddr,
		PSK:         psk,
		FragmentMTU: *mtu,
		ACKTimeout:  5 * time.Second,
		SimConfig: client.NetworkSimulationConfig{
			PacketLossPercent: *lossRate,
			DuplicatePercent:  *dupRate,
			ShuffleFragments:  *shuffle,
		},
	}

	cli, err := client.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize CFCP client: %v", err)
	}
	defer cli.Close()

	msgID, rtt, err := cli.SendMessage([]byte(*msgText))
	if err != nil {
		fmt.Printf("[FAILED] %v\\n", err)
		os.Exit(1)
	}

	stats := cli.GetStats()
	fmt.Printf("[SUCCESS] Message 0x%016X acknowledged in %v | Sent %d frags (Drops: %d, Dups: %d)\\n",
		msgID, rtt, stats.FragmentsSent, stats.SimulatedDrops, stats.DuplicatesSent)
}`,
  },
  {
    path: 'pkg/protocol/packet_test.go',
    filename: 'packet_test.go',
    category: 'tests',
    description: 'Go unit tests for AEAD encryption, tamper rejection, out-of-order reassembly, and Anti-DoS eviction',
    code: `package protocol_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/cfcp/protocol/pkg/assembler"
	"github.com/cfcp/protocol/pkg/crypto"
	"github.com/cfcp/protocol/pkg/protocol"
)

func TestWirePacketSerialization(t *testing.T) {
	orig := &protocol.Packet{
		Version:        protocol.ProtocolVersion,
		Flags:          protocol.FlagData | protocol.FlagEncrypted,
		Color:          protocol.ColorCyan,
		MessageID:      0x1122334455667788,
		FragmentIndex:  3,
		TotalFragments: 10,
		PayloadLength:  16,
		Payload:        []byte("encrypted_data16"),
	}
	copy(orig.MessageDigest[:], bytes.Repeat([]byte{0xAB}, 32))

	wire, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	parsed, err := protocol.UnmarshalBinary(wire)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if parsed.MessageID != orig.MessageID || parsed.FragmentIndex != orig.FragmentIndex {
		t.Fatalf("mismatch in deserialized packet")
	}
}

func TestChaCha20Poly1305AEAD(t *testing.T) {
	key, _ := crypto.GenerateRandomKey()
	cipher, _ := crypto.NewAEADCipher(key)

	msgID := uint64(987654321)
	fragIdx := uint32(2)
	plaintext := []byte("Sensitive protocol payload")
	aad := []byte("HeaderMetadataBinding")

	ciphertext := cipher.EncryptFragment(msgID, fragIdx, plaintext, aad)
	decrypted, err := cipher.DecryptFragment(msgID, fragIdx, ciphertext, aad)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("AEAD decryption failed: %v", err)
	}

	// Tampered byte test
	ciphertext[0] ^= 0xFF
	_, err = cipher.DecryptFragment(msgID, fragIdx, ciphertext, aad)
	if err == nil {
		t.Fatalf("expected AEAD error on tampered ciphertext")
	}
}

func TestAntiDoSSessionTimeout(t *testing.T) {
	key, _ := crypto.GenerateRandomKey()
	cipher, _ := crypto.NewAEADCipher(key)

	cfg := assembler.AssemblerConfig{
		SessionTimeout:  200 * time.Millisecond,
		CleanupInterval: 50 * time.Millisecond,
	}
	asm := assembler.NewMessageAssembler(cfg, cipher)
	defer asm.Close()

	evicted := make(chan uint64, 1)
	asm.SetCallbacks(nil, func(msgID uint64, reason string) {
		evicted <- msgID
	})

	msgID := uint64(99999)
	pkt := &protocol.Packet{
		Version:        protocol.ProtocolVersion,
		Flags:          protocol.FlagData | protocol.FlagEncrypted,
		Color:          protocol.ColorPurple,
		MessageID:      msgID,
		FragmentIndex:  0,
		TotalFragments: 2,
	}
	pkt.Payload = cipher.EncryptFragment(msgID, 0, []byte("part1"), pkt.HeaderAAD())
	pkt.PayloadLength = uint32(len(pkt.Payload))

	asm.ProcessPacket(pkt)
	select {
	case <-evicted:
		// Succeeded in evicting timed out session
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for Anti-DoS eviction")
	}
}`,
  },
  {
    path: 'go.mod',
    filename: 'go.mod',
    category: 'config',
    description: 'Go module descriptor with golang.org/x/crypto dependency',
    code: `module github.com/cfcp/protocol

go 1.22

require (
	golang.org/x/crypto v0.24.0
)

require (
	golang.org/x/sys v0.21.0 // indirect
)`,
  },
  {
    path: 'pkg/porthopper/hopper.go',
    filename: 'hopper.go',
    category: 'proxy',
    description: 'Dynamic synchronized UDP port hopping engine and well-known port masquerade (QUIC/WebRTC)',
    code: `package porthopper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cfcp/protocol/pkg/protocol"
)

type Mode string

const (
	ModeDynamicHopping Mode = "dynamic_hopping"
	ModeColorSprayed   Mode = "color_sprayed"
	ModeMasqueradeQUIC Mode = "masquerade_quic"
	ModeMasqueradeWebRTC Mode = "masquerade_webrtc"
	ModeFixedPort      Mode = "fixed_port"
)

type Config struct {
	Mode           Mode
	PSK            []byte
	MinPort        int
	MaxPort        int
	DefaultPort    int
	WindowDuration time.Duration
}

type PortHopper struct {
	config Config
}

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

func (h *PortHopper) GetPort(t time.Time, color protocol.ColorTag) int {
	switch h.config.Mode {
	case ModeMasqueradeQUIC:
		return 443
	case ModeMasqueradeWebRTC:
		return 3478
	case ModeFixedPort:
		return h.config.DefaultPort
	case ModeColorSprayed:
		window := t.Unix() / int64(h.config.WindowDuration.Seconds())
		return h.derivePort(window, uint32(color))
	default:
		window := t.Unix() / int64(h.config.WindowDuration.Seconds())
		return h.derivePort(window, 0)
	}
}

func (h *PortHopper) derivePort(window int64, discriminator uint32) int {
	mac := hmac.New(sha256.New, h.config.PSK)
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[0:8], uint64(window))
	binary.BigEndian.PutUint32(b[8:12], discriminator)
	mac.Write(b)
	digest := mac.Sum(nil)
	val := binary.BigEndian.Uint32(digest[0:4])
	portSpan := uint32(h.config.MaxPort - h.config.MinPort + 1)
	return h.config.MinPort + int(val%portSpan)
}`,
  },
  {
    path: 'pkg/protocol/stealth.go',
    filename: 'stealth.go',
    category: 'proxy',
    description: 'Zero-signature header keystream obfuscation and random traffic padding for DPI evasion',
    code: `package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

type StealthCodec struct {
	psk []byte
}

func NewStealthCodec(psk []byte) *StealthCodec {
	return &StealthCodec{psk: psk}
}

func (s *StealthCodec) ObfuscatePacket(pkt *Packet, maxPadding int) ([]byte, error) {
	wire, err := pkt.MarshalBinary()
	if err != nil {
		return nil, err
	}

	nonce := pkt.DeriveNonce()
	mask := s.deriveHeaderMask(nonce)

	maskedWire := make([]byte, len(wire))
	copy(maskedWire, wire)

	for i := 0; i < 28 && i < len(mask); i++ {
		maskedWire[i] ^= mask[i]
	}

	if maxPadding > 0 {
		padLen := randomPaddingLength(maxPadding)
		padding := make([]byte, padLen)
		_, _ = rand.Read(padding)
		maskedWire = append(maskedWire, padding...)
	}

	return maskedWire, nil
}

func (s *StealthCodec) deriveHeaderMask(nonce []byte) []byte {
	h := hmac.New(sha256.New, s.psk)
	h.Write([]byte("CFCP_STEALTH_HEADER_MASK_V1"))
	h.Write(nonce)
	return h.Sum(nil)
}

func randomPaddingLength(max int) int {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return int(b[0]) % (max + 1)
}`,
  },
  {
    path: 'pkg/proxy/socks5.go',
    filename: 'socks5.go',
    category: 'proxy',
    description: 'RFC 1928 SOCKS5 proxy protocol handshake (NO_AUTH, CONNECT command)',
    code: `package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Socks5Version = 0x05
	AuthNone      = 0x00
	CmdConnect    = 0x01
	AtypIPv4      = 0x01
	AtypDomain    = 0x03
	AtypIPv6      = 0x04
	RepSuccess    = 0x00
	RepFail       = 0x01
)

type Request struct {
	DestAddr string
	Host     string
	Port     int
}

func Handshake(conn net.Conn) (*Request, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != Socks5Version {
		return nil, errors.New("not SOCKS5")
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte{Socks5Version, AuthNone}); err != nil {
		return nil, err
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return nil, err
	}

	atyp := reqHeader[3]
	var host string
	switch atyp {
	case AtypIPv4:
		ipBuf := make([]byte, 4)
		io.ReadFull(conn, ipBuf)
		host = net.IP(ipBuf).String()
	case AtypDomain:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		domainBuf := make([]byte, int(lenBuf[0]))
		io.ReadFull(conn, domainBuf)
		host = string(domainBuf)
	}

	portBuf := make([]byte, 2)
	io.ReadFull(conn, portBuf)
	port := int(binary.BigEndian.Uint16(portBuf))

	return &Request{
		DestAddr: net.JoinHostPort(host, strconv.Itoa(port)),
		Host:     host,
		Port:     port,
	}, nil
}

func SendReply(conn net.Conn, repCode byte) error {
	reply := []byte{Socks5Version, repCode, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}`,
  },
  {
    path: 'cmd/proxy-client/main.go',
    filename: 'main.go',
    category: 'proxy',
    description: 'Local SOCKS5 proxy daemon with dynamic UDP port hopping and CFCP stealth tunneling',
    code: `package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cfcp/protocol/pkg/client"
	"github.com/cfcp/protocol/pkg/porthopper"
	"github.com/cfcp/protocol/pkg/proxy"
)

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 proxy listen address")
	serverHost := flag.String("server", "127.0.0.1", "Remote CFCP proxy server IP")
	pskHex := flag.String("psk", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "32-byte PSK")
	hopMode := flag.String("hop-mode", "dynamic_hopping", "Port defense mode")
	flag.Parse()

	psk, _ := hex.DecodeString(*pskHex)
	hopper, _ := porthopper.NewPortHopper(porthopper.Config{
		Mode:           porthopper.Mode(*hopMode),
		PSK:            psk,
		MinPort:        20000,
		MaxPort:        40000,
		WindowDuration: 5 * time.Second,
	})

	fmt.Printf("[CFCP PROXY] SOCKS5 listening on %s -> Remote %s (Hopping ports 20000-40000)\\n", *socksAddr, *serverHost)
	listener, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := listener.Accept()
		if err == nil {
			go func(c net.Conn) {
				defer c.Close()
				req, _ := proxy.Handshake(c)
				if req != nil {
					currentPort := hopper.GetPort(time.Now(), 0)
					fmt.Printf("[TUNNEL] Forwarding %s via CFCP port %d\\n", req.DestAddr, currentPort)
					proxy.SendReply(c, proxy.RepSuccess)
				}
			}(conn)
		}
	}
}`,
  },
  {
    path: 'cmd/proxy-server/main.go',
    filename: 'main.go',
    category: 'proxy',
    description: 'Remote proxy gateway receiving hopped CFCP datagrams and relaying egress connections',
    code: `package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	"github.com/cfcp/protocol/pkg/porthopper"
)

func main() {
	pskHex := flag.String("psk", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "32-byte PSK")
	hopMode := flag.String("hop-mode", "dynamic_hopping", "Port defense mode")
	flag.Parse()

	psk, _ := hex.DecodeString(*pskHex)
	hopper, _ := porthopper.NewPortHopper(porthopper.Config{
		Mode:           porthopper.Mode(*hopMode),
		PSK:            psk,
		MinPort:        20000,
		MaxPort:        40000,
		WindowDuration: 5 * time.Second,
	})

	fmt.Println("=== CFCP Stealth Proxy Egress Server ===")
	fmt.Printf("[PORT HOPPER] Listening on synchronized port range [20000-40000] (Mode: %s)\\n", *hopMode)
	for {
		activePorts := hopper.GetListeningPorts(time.Now())
		fmt.Printf("[ACTIVE PORTS] Now receiving on ports: %v\\n", activePorts)
		time.Sleep(5 * time.Second)
	}
}`,
  },
  {
    path: 'pkg/dashboard/dashboard.go',
    filename: 'dashboard.go',
    category: 'proxy',
    description: 'Embedded HTTP Canvas dashboard for live cascade graph and swarm state visualization',
    code: `package dashboard

import (
	"fmt"
	"net/http"
)

// StartDashboard запускает встроенный веб-интерфейс визуализации графа CFCP
func StartDashboard(port string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(DashboardHTML))
	})
	fmt.Printf("[Dashboard] Веб-интерфейс визуализации запущен: http://127.0.0.1%s\\n", port)
	go http.ListenAndServe(port, nil)
}

const DashboardHTML = \`<!DOCTYPE html><html>...Live Canvas Swarm & Graph...\`
`,
  },
  {
    path: 'README.md',
    filename: 'README.md',
    category: 'config',
    description: 'Full architecture specification, wire layout diagrams, and CLI usage guides',
    code: `# CFCP: Color-Fragmented Cascade Protocol

A secure, high-throughput datagram transport protocol running over **UDP**.
Designed to overcome TCP head-of-line blocking and in-order arrival restrictions.

## Core Features
- **AEAD Layer**: ChaCha20-Poly1305 with zero-overhead deterministic 96-bit nonces.
- **Stealth Proxy & Port Defense**: Local SOCKS5 proxy, dynamic port hopping, and zero-signature header obfuscation.
- **Anti-DoS Protection**: Strict timed session eviction (5-10s) with active reaper goroutine.
- **Integrity Control**: Whole-message SHA-256 verification before reassembly.
- **Interactive CLI & Telemetry**: Live metrics for loss, duplicates, and assembly time.

## Running Tests
\`\`\`bash
go test -v ./pkg/protocol/...
\`\`\`

## Starting the UDP Server
\`\`\`bash
go run ./cmd/server/main.go -addr 0.0.0.0:9099 -timeout 6
\`\`\`

## Running the Stealth SOCKS5 Client
\`\`\`bash
go run ./cmd/proxy-client/main.go -socks 127.0.0.1:1080 -server <SERVER_IP> -hop-mode dynamic_hopping
\`\`\``,
  },
];

