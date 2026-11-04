#!/usr/bin/env bash
set -e

# ==============================================================================
# CFCP (Color-Fragmented Cascade Protocol) — Automated Installer & Setup
# Zero-Configuration Installer for Linux & macOS (x86_64 / arm64)
# ==============================================================================

BOLD="\033[1m"
GREEN="\033[32m"
BLUE="\033[34m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "  ██████╗███████╗ ██████╗██████╗ "
echo " ██╔════╝██╔════╝██╔════╝██╔══██╗"
echo " ██║     █████╗  ██║     ██████╔╝"
echo " ██║     ██╔══╝  ██║     ██╔═══╝ "
echo " ╚██████╗██║     ╚██████╗██║     "
echo "  ╚═════╝╚═╝      ╚═════╝╚═╝     "
echo -e "${RESET}"
echo -e "${BOLD}Color-Fragmented Cascade Protocol (CFCP) Installer${RESET}"
echo -e "AEAD ChaCha20-Poly1305 · Anti-DoS Timed Reassembly · Dynamic Port Hopping\n"

# 1. System & Architecture Detection
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    GO_ARCH="amd64"
    ;;
  arm64|aarch64)
    GO_ARCH="arm64"
    ;;
  *)
    echo -e "${RED}[ERROR] Unsupported CPU architecture: $ARCH${RESET}"
    exit 1
    ;;
esac

case "$OS" in
  linux)
    GO_OS="linux"
    ;;
  darwin)
    GO_OS="darwin"
    ;;
  *)
    echo -e "${RED}[ERROR] Unsupported operating system: $OS (requires Linux or macOS)${RESET}"
    exit 1
    ;;
esac

echo -e "${BLUE}[*] Detected platform:${RESET} ${GO_OS}-${GO_ARCH}"

# 2. Check or Install Go Toolchain
INSTALL_DIR="$HOME/cfcp"
GO_REQUIRED_VER="1.22.4"
GO_CMD=""

if command -v go >/dev/null 2>&1; then
  CURRENT_GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
  echo -e "${GREEN}[✓] Found existing Go toolchain:${RESET} go$CURRENT_GO_VER"
  GO_CMD="go"
else
  # Install standalone Go into user home directory
  USER_GO_DIR="$HOME/.cfcp-go"
  echo -e "${YELLOW}[!] Go compiler not found in PATH.${RESET}"
  echo -e "${BLUE}[*] Installing standalone Go ${GO_REQUIRED_VER} to ${USER_GO_DIR}...${RESET}"
  
  mkdir -p "$USER_GO_DIR"
  GO_TARBALL_URL="https://go.dev/dl/go${GO_REQUIRED_VER}.${GO_OS}-${GO_ARCH}.tar.gz"
  
  if command -v curl >/dev/null 2>&1; then
    curl -sSL "$GO_TARBALL_URL" -o "/tmp/go_installer.tar.gz"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$GO_TARBALL_URL" -O "/tmp/go_installer.tar.gz"
  else
    echo -e "${RED}[ERROR] Neither curl nor wget is available. Please install curl.${RESET}"
    exit 1
  fi
  
  tar -C "$USER_GO_DIR" --strip-components=1 -xzf "/tmp/go_installer.tar.gz"
  rm -f "/tmp/go_installer.tar.gz"
  
  export PATH="$USER_GO_DIR/bin:$PATH"
  GO_CMD="$USER_GO_DIR/bin/go"
  echo -e "${GREEN}[✓] Go ${GO_REQUIRED_VER} installed successfully.${RESET}"
fi

# 3. Create Project Directory Tree
echo -e "${BLUE}[*] Setting up CFCP workspace in ${INSTALL_DIR}...${RESET}"
mkdir -p "$INSTALL_DIR/pkg/protocol"
mkdir -p "$INSTALL_DIR/pkg/crypto"
mkdir -p "$INSTALL_DIR/pkg/assembler"
mkdir -p "$INSTALL_DIR/pkg/porthopper"
mkdir -p "$INSTALL_DIR/pkg/proxy"
mkdir -p "$INSTALL_DIR/pkg/dashboard"
mkdir -p "$INSTALL_DIR/pkg/server"
mkdir -p "$INSTALL_DIR/pkg/client"
mkdir -p "$INSTALL_DIR/cmd/server"
mkdir -p "$INSTALL_DIR/cmd/client"
mkdir -p "$INSTALL_DIR/cmd/proxy-server"
mkdir -p "$INSTALL_DIR/cmd/proxy-client"
mkdir -p "$INSTALL_DIR/bin"

# 4. Generate go.mod
cat << 'EOF' > "$INSTALL_DIR/go.mod"
module github.com/cfcp/protocol

go 1.22

require (
	golang.org/x/crypto v0.24.0
)

require (
	golang.org/x/sys v0.21.0 // indirect
)
EOF

# 5. Generate pkg/protocol/packet.go
cat << 'EOF' > "$INSTALL_DIR/pkg/protocol/packet.go"
package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	MagicBytes       = [4]byte{'C', 'F', 'C', 'P'}
	ProtocolVersion  uint8 = 1
	HeaderSize       = 60
	MaxPayloadSize   = 65507 - HeaderSize
	DefaultMTUSize   = 1200
)

const (
	FlagData        uint8 = 0x01
	FlagACK         uint8 = 0x02
	FlagEncrypted   uint8 = 0x04
	FlagRetransmit  uint8 = 0x08
	FlagHeartbeat   uint8 = 0x10
)

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
	buf[7] = 0x00

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

func (p *Packet) HeaderAAD() []byte {
	aad := make([]byte, 24)
	copy(aad[0:4], MagicBytes[:])
	aad[4] = p.Version
	aad[5] = p.Flags
	aad[6] = uint8(p.Color)
	aad[7] = 0x00
	binary.BigEndian.PutUint64(aad[8:16], p.MessageID)
	binary.BigEndian.PutUint32(aad[16:20], p.FragmentIndex)
	binary.BigEndian.PutUint32(aad[20:24], p.TotalFragments)
	return aad
}

func (p *Packet) DeriveNonce(baseNonce []byte) []byte {
	nonce := make([]byte, 12)
	if len(baseNonce) > 0 {
		copy(nonce, baseNonce)
	}

	var idBytes [8]byte
	binary.BigEndian.PutUint64(idBytes[:], p.MessageID)
	for i, b := range idBytes {
		if 4+i < 12 {
			nonce[4+i] ^= b
		}
	}

	var idxBytes [4]byte
	binary.BigEndian.PutUint32(idxBytes[:], p.FragmentIndex)
	for i, b := range idxBytes {
		nonce[i] ^= b
	}

	return nonce
}
EOF

# 6. Generate pkg/crypto/aead.go
cat << 'EOF' > "$INSTALL_DIR/pkg/crypto/aead.go"
package crypto

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
	KeySize   = chacha20poly1305.KeySize
	NonceSize = chacha20poly1305.NonceSize
	TagSize   = chacha20poly1305.Overhead
)

var (
	ErrInvalidKeySize     = errors.New("cfcp/crypto: key must be exactly 32 bytes")
	ErrDecryptionFailed   = errors.New("cfcp/crypto: AEAD authentication failed (tampered or corrupt)")
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
}
EOF

# 7. Generate pkg/assembler/assembler.go
cat << 'EOF' > "$INSTALL_DIR/pkg/assembler/assembler.go"
package assembler

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
		MaxSessionMemoryBytes: 4 * 1024 * 1024,
		MaxTotalMemoryBytes:   64 * 1024 * 1024,
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

func (ma *MessageAssembler) SetCallbacks(
	onComplete func(msg *CompletedMessage),
	onEvict func(msgID uint64, reason string),
) {
	ma.mu.Lock()
	defer ma.mu.Unlock()
	ma.onComplete = onComplete
	ma.onEvict = onEvict
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
		return nil, ErrDuplicateFragment
	}

	var plaintext []byte
	var err error
	if pkt.Flags&protocol.FlagEncrypted != 0 && ma.cipher != nil {
		aad := pkt.HeaderAAD()
		plaintext, err = ma.cipher.DecryptFragment(pkt.MessageID, pkt.FragmentIndex, pkt.Payload, aad)
		if err != nil {
			return nil, fmt.Errorf("AEAD fragment decryption failed: %w", err)
		}
	} else {
		plaintext = make([]byte, len(pkt.Payload))
		copy(plaintext, pkt.Payload)
	}

	fragMemory := len(plaintext) + int(pkt.PayloadLength) + 64
	if session.AllocatedBytes+fragMemory > ma.config.MaxSessionMemoryBytes {
		return nil, ErrSessionMemoryExceeded
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

	if session.ReceivedCount == session.TotalFragments {
		assemblyDuration := time.Since(session.CreatedAt)
		var assembledBuffer bytes.Buffer
		for i := uint32(0); i < session.TotalFragments; i++ {
			assembledBuffer.Write(session.Slots[i].Plaintext)
		}
		assembledBytes := assembledBuffer.Bytes()

		actualDigest := crypto.ComputeMessageDigest(assembledBytes)
		if !bytes.Equal(actualDigest[:], session.ExpectedDigest[:]) {
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
			delete(ma.sessions, msgID)
			if ma.onEvict != nil {
				ma.onEvict(msgID, "Anti-DoS session timeout")
			}
		}
	}
}
EOF

# 8. Generate pkg/porthopper/hopper.go
cat << 'EOF' > "$INSTALL_DIR/pkg/porthopper/hopper.go"
package porthopper

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

func (h *PortHopper) GetListeningPorts(t time.Time) []int {
	switch h.config.Mode {
	case ModeMasqueradeQUIC:
		return []int{443}
	case ModeMasqueradeWebRTC:
		return []int{3478}
	case ModeFixedPort:
		return []int{h.config.DefaultPort}
	default:
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
}
EOF

# 9. Generate pkg/server/server.go
cat << 'EOF' > "$INSTALL_DIR/pkg/server/server.go"
package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
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

type Server struct {
	config    ServerConfig
	cipher    *crypto.AEADCipher
	assembler *assembler.MessageAssembler
	conn      *net.UDPConn
	stopChan  chan struct{}
	wg        sync.WaitGroup
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
		return err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
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

		pkt, err := protocol.UnmarshalBinary(buffer[:n])
		if err != nil {
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
}
EOF

# 10. Generate pkg/client/client.go
cat << 'EOF' > "$INSTALL_DIR/pkg/client/client.go"
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
	raddr, err := net.ResolveUDPAddr("udp", c.config.ServerAddr)
	if err != nil {
		return 0, 0, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	startTime := time.Now()
	b := make([]byte, 8)
	rand.Read(b)
	msgID := binary.BigEndian.Uint64(b)
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
		wireBytes, err := pkt.MarshalBinary()
		if err != nil {
			return msgID, 0, err
		}
		if _, err := conn.Write(wireBytes); err != nil {
			return msgID, 0, err
		}
	}

	conn.SetReadDeadline(time.Now().Add(c.config.ACKTimeout))
	ackBuf := make([]byte, 1024)
	n, err := conn.Read(ackBuf)
	if err != nil {
		return msgID, 0, fmt.Errorf("awaiting ACK timeout or error: %w", err)
	}

	ackPkt, err := protocol.UnmarshalBinary(ackBuf[:n])
	if err != nil {
		return msgID, 0, err
	}

	if ackPkt.MessageID != msgID || (ackPkt.Flags&protocol.FlagACK == 0) {
		return msgID, 0, errors.New("received invalid ACK")
	}

	return msgID, time.Since(startTime), nil
}
EOF

# 11. Generate cmd/server/main.go
cat << 'EOF' > "$INSTALL_DIR/cmd/server/main.go"
package main

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
	listenAddr := flag.String("addr", "0.0.0.0:9099", "UDP listen address")
	pskHex := flag.String("psk", defaultHexPSK, "32-byte Hex PSK")
	timeoutSec := flag.Int("timeout", 6, "Anti-DoS session timeout")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be a 64-character hexadecimal string")
	}

	fmt.Println("=================================================================")
	fmt.Println("       CFCP Server (Color-Fragmented Cascade Protocol)           ")
	fmt.Println("=================================================================")
	fmt.Printf(" [CONFIG] Listen: %s | Anti-DoS Timeout: %ds\n", *listenAddr, *timeoutSec)
	fmt.Println("-----------------------------------------------------------------")

	cfg := server.ServerConfig{
		ListenAddr: *listenAddr,
		PSK:        psk,
		AssemblerConfig: assembler.AssemblerConfig{
			SessionTimeout:        time.Duration(*timeoutSec) * time.Second,
			CleanupInterval:       1 * time.Second,
			MaxConcurrentSessions: 1024,
			MaxSessionMemoryBytes: 4 * 1024 * 1024,
			MaxTotalMemoryBytes:   64 * 1024 * 1024,
		},
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("Init server error: %v", err)
	}

	srv.OnMessage(func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr) {
		preview := string(msg.Payload)
		if len(preview) > 50 {
			preview = preview[:47] + "..."
		}
		fmt.Printf(" \033[32m[✓ Message Assembled]\033[0m ID: 0x%016X | From: %s\n", msg.MessageID, remoteAddr.String())
		fmt.Printf("   Fragments: %d | Time: %v | Size: %d B\n", msg.TotalFragments, msg.AssemblyTime, len(msg.Payload))
		fmt.Printf("   Arrival  : %v | Payload: %q\n", msg.ArrivalOrder, preview)
		fmt.Println("-----------------------------------------------------------------")
	})

	if err := srv.Start(); err != nil {
		log.Fatalf("Start server error: %v", err)
	}
	defer srv.Stop()

	fmt.Printf("Listening on UDP %s. Press Ctrl+C to stop.\n", *listenAddr)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nServer shutdown.")
}
EOF

# 12. Generate cmd/client/main.go
cat << 'EOF' > "$INSTALL_DIR/cmd/client/main.go"
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cfcp/protocol/pkg/client"
)

const defaultHexPSK = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

func main() {
	serverAddr := flag.String("addr", "127.0.0.1:9099", "CFCP UDP server address")
	pskHex := flag.String("psk", defaultHexPSK, "32-byte Hex PSK")
	msgText := flag.String("msg", "Testing CFCP Color-Fragmented Cascade Datagram Transmission over UDP!", "Message to send")
	mtu := flag.Int("mtu", 32, "Fragment payload chunk size")
	shuffle := flag.Bool("shuffle", true, "Shuffle fragments out-of-order")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be 64-character hexadecimal string")
	}

	cfg := client.ClientConfig{
		ServerAddr:  *serverAddr,
		PSK:         psk,
		FragmentMTU: *mtu,
		SimConfig: client.NetworkSimulationConfig{
			ShuffleFragments: *shuffle,
		},
	}

	cli, err := client.NewClient(cfg)
	if err != nil {
		log.Fatalf("Client init error: %v", err)
	}

	fmt.Println("Encrypting and dispatching cascade fragments...")
	msgID, rtt, err := cli.SendMessage([]byte(*msgText))
	if err != nil {
		fmt.Printf("\033[31m[FAILED]\033[0m %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\033[32m[SUCCESS]\033[0m Message 0x%016X acknowledged in %v!\n", msgID, rtt)
}
EOF

# 13. Download Dependencies & Run Unit Tests
echo -e "\n${BLUE}[*] Fetching dependencies (golang.org/x/crypto)...${RESET}"
(cd "$INSTALL_DIR" && $GO_CMD mod tidy)

echo -e "\n${BLUE}[*] Running CFCP automated test suite...${RESET}"
(cd "$INSTALL_DIR" && $GO_CMD test -v ./pkg/protocol/...)

# 14. Compile Executable Binaries
echo -e "\n${BLUE}[*] Compiling CFCP production binaries...${RESET}"
(cd "$INSTALL_DIR" && $GO_CMD build -o "$INSTALL_DIR/bin/cfcp-server" ./cmd/server)
(cd "$INSTALL_DIR" && $GO_CMD build -o "$INSTALL_DIR/bin/cfcp-client" ./cmd/client)

# 15. Create Quickstart Helper Scripts
cat << 'EOF' > "$INSTALL_DIR/run-server.sh"
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/bin/cfcp-server" -addr 0.0.0.0:9099 -timeout 6
EOF
chmod +x "$INSTALL_DIR/run-server.sh"

cat << 'EOF' > "$INSTALL_DIR/run-client.sh"
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$SCRIPT_DIR/bin/cfcp-client" -addr 127.0.0.1:9099 -msg "CFCP Live Packet Transmission" -mtu 32 -shuffle=true
EOF
chmod +x "$INSTALL_DIR/run-client.sh"

echo -e "\n${GREEN}${BOLD}=================================================================${RESET}"
echo -e "${GREEN}${BOLD}       CFCP Protocol Suite Installed Successfully!                ${RESET}"
echo -e "${GREEN}${BOLD}=================================================================${RESET}"
echo -e "Location:  ${CYAN}${INSTALL_DIR}${RESET}"
echo -e "Binaries:  ${CYAN}${INSTALL_DIR}/bin/cfcp-server${RESET}"
echo -e "           ${CYAN}${INSTALL_DIR}/bin/cfcp-client${RESET}\n"
echo -e "${BOLD}Quickstart commands:${RESET}"
echo -e "  1. Start UDP Server:    ${YELLOW}cd ~/cfcp && ./run-server.sh${RESET}"
echo -e "  2. Send Test Cascade:   ${YELLOW}cd ~/cfcp && ./run-client.sh${RESET}"
echo -e "  3. Run Unit Tests:      ${YELLOW}cd ~/cfcp && go test -v ./pkg/protocol/...${RESET}\n"
EOF
