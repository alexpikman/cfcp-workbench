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
	ErrSessionTimedOut      = errors.New("cfcp/assembler: session timed out during assembly")
	ErrSessionMemoryExceeded = errors.New("cfcp/assembler: message memory quota exceeded (Anti-DoS)")
	ErrTotalMemoryExceeded  = errors.New("cfcp/assembler: total assembler memory pool exhausted (Anti-DoS)")
	ErrMaxSessionsReached   = errors.New("cfcp/assembler: max concurrent sessions cap reached (Anti-DoS)")
	ErrDuplicateFragment    = errors.New("cfcp/assembler: duplicate fragment ignored")
	ErrIntegrityHashMismatch = errors.New("cfcp/assembler: SHA-256 message digest integrity verification failed")
	ErrFragmentCountMismatch = errors.New("cfcp/assembler: fragment total count inconsistent with existing session")
)

// AssemblerConfig defines memory boundaries and Anti-DoS parameters.
type AssemblerConfig struct {
	SessionTimeout       time.Duration // Time before incomplete session is evicted (e.g. 5-10s)
	CleanupInterval      time.Duration // Reaper interval for periodic garbage collection (e.g. 1s)
	MaxConcurrentSessions int           // Maximum number of open sessions allowed simultaneously
	MaxSessionMemoryBytes int           // Max memory allowed for a single message session (e.g. 4MB)
	MaxTotalMemoryBytes   int           // Max cumulative memory across all active sessions (e.g. 64MB)
}

// DefaultConfig provides conservative Anti-DoS defaults.
func DefaultConfig() AssemblerConfig {
	return AssemblerConfig{
		SessionTimeout:        6 * time.Second,
		CleanupInterval:       1 * time.Second,
		MaxConcurrentSessions: 1024,
		MaxSessionMemoryBytes: 4 * 1024 * 1024,  // 4 MB
		MaxTotalMemoryBytes:   64 * 1024 * 1024, // 64 MB
	}
}

// FragmentSlot holds one received fragment.
type FragmentSlot struct {
	Index         uint32
	ReceivedAt    time.Time
	CiphertextLen uint32
	Plaintext     []byte
	Color         protocol.ColorTag
}

// AssemblySession tracks an in-flight message assembly.
type AssemblySession struct {
	MessageID       uint64
	TotalFragments  uint32
	ReceivedCount   uint32
	ExpectedDigest  [32]byte
	CreatedAt       time.Time
	LastActivityAt  time.Time
	AllocatedBytes  int
	Slots           []*FragmentSlot
	ArrivalOrder    []uint32 // sequence of fragment arrival for telemetry
}

// AssemblerStats records telemetry and health metrics.
type AssemblerStats struct {
	ActiveSessions    int           `json:"active_sessions"`
	CompletedSessions uint64        `json:"completed_sessions"`
	TimedOutSessions  uint64        `json:"timed_out_sessions"`
	DuplicatePackets  uint64        `json:"duplicate_packets"`
	CorruptedPackets  uint64        `json:"corrupted_packets"`
	HashFailures      uint64        `json:"hash_failures"`
	CurrentMemoryBytes int          `json:"current_memory_bytes"`
	AvgAssemblyTime   time.Duration `json:"avg_assembly_time"`
}

// CompletedMessage represents a successfully validated and assembled message.
type CompletedMessage struct {
	MessageID      uint64
	Payload        []byte
	Digest         [32]byte
	TotalFragments uint32
	AssemblyTime   time.Duration
	ArrivalOrder   []uint32
}

// MessageAssembler receives out-of-order UDP datagrams, enforces strict
// Anti-DoS timeouts, decrypts via AEAD ChaCha20-Poly1305, and verifies
// whole-message SHA-256 integrity before releasing assembled payloads.
type MessageAssembler struct {
	config  AssemblerConfig
	cipher  *crypto.AEADCipher
	mu      sync.RWMutex
	sessions map[uint64]*AssemblySession

	stats      AssemblerStats
	totalTime  time.Duration

	// Reaper control
	stopReaper chan struct{}
	wg         sync.WaitGroup

	// Callbacks (optional)
	onComplete func(msg *CompletedMessage)
	onEvict    func(msgID uint64, reason string)
}

// NewMessageAssembler constructs and starts the background Anti-DoS reaper.
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

// Close gracefully stops the background Anti-DoS reaper.
func (ma *MessageAssembler) Close() {
	close(ma.stopReaper)
	ma.wg.Wait()
}

// SetCallbacks registers event handlers for completed and evicted sessions.
func (ma *MessageAssembler) SetCallbacks(
	onComplete func(msg *CompletedMessage),
	onEvict func(msgID uint64, reason string),
) {
	ma.mu.Lock()
	defer ma.mu.Unlock()
	ma.onComplete = onComplete
	ma.onEvict = onEvict
}

// ProcessPacket ingests a single incoming packet. If the packet completes
// the message, it verifies the SHA-256 digest, decrypts/assembles, and
// returns the CompletedMessage.
func (ma *MessageAssembler) ProcessPacket(pkt *protocol.Packet) (*CompletedMessage, error) {
	if pkt == nil {
		return nil, errors.New("cfcp/assembler: nil packet")
	}

	ma.mu.Lock()
	defer ma.mu.Unlock()

	// Check if this is a data packet
	if pkt.Flags&protocol.FlagData == 0 {
		return nil, nil // Non-data packet (e.g. pure ACK)
	}

	session, exists := ma.sessions[pkt.MessageID]

	// 1. Anti-DoS: Check session limit and create session if new
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

	// Invariant validation
	if session.TotalFragments != pkt.TotalFragments {
		return nil, ErrFragmentCountMismatch
	}
	if pkt.FragmentIndex >= session.TotalFragments {
		return nil, protocol.ErrInvalidFragmentNo
	}

	// 2. Duplicate Detection: Check if fragment was already received
	if session.Slots[pkt.FragmentIndex] != nil {
		ma.stats.DuplicatePackets++
		return nil, ErrDuplicateFragment
	}

	// 3. Decrypt fragment with ChaCha20-Poly1305 AEAD
	// Notice: We pass the packet's Header AAD to verify header integrity
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
		// Unencrypted payload fallback
		plaintext = make([]byte, len(pkt.Payload))
		copy(plaintext, pkt.Payload)
	}

	// 4. Memory Quota Check (Anti-DoS)
	fragMemory := len(plaintext) + int(pkt.PayloadLength) + 64 // Overhead estimation
	if session.AllocatedBytes+fragMemory > ma.config.MaxSessionMemoryBytes {
		ma.stats.CorruptedPackets++
		return nil, ErrSessionMemoryExceeded
	}
	if ma.stats.CurrentMemoryBytes+fragMemory > ma.config.MaxTotalMemoryBytes {
		return nil, ErrTotalMemoryExceeded
	}

	// Allocate slot
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

	// 5. Check if all fragments are received
	if session.ReceivedCount == session.TotalFragments {
		assemblyDuration := time.Since(session.CreatedAt)

		// Glue all fragments in deterministic index order (0 .. TotalFragments-1)
		var assembledBuffer bytes.Buffer
		for i := uint32(0); i < session.TotalFragments; i++ {
			assembledBuffer.Write(session.Slots[i].Plaintext)
		}
		assembledBytes := assembledBuffer.Bytes()

		// 6. Integrity Control: Verify SHA-256 Digest BEFORE Releasing
		actualDigest := crypto.ComputeMessageDigest(assembledBytes)
		if !bytes.Equal(actualDigest[:], session.ExpectedDigest[:]) {
			ma.stats.HashFailures++
			// Clean up memory
			ma.stats.CurrentMemoryBytes -= session.AllocatedBytes
			delete(ma.sessions, pkt.MessageID)
			return nil, fmt.Errorf("%w: expected %x, calculated %x", ErrIntegrityHashMismatch, session.ExpectedDigest, actualDigest)
		}

		// Reassembly succeeded!
		completed := &CompletedMessage{
			MessageID:      session.MessageID,
			Payload:        assembledBytes,
			Digest:         actualDigest,
			TotalFragments: session.TotalFragments,
			AssemblyTime:   assemblyDuration,
			ArrivalOrder:   append([]uint32(nil), session.ArrivalOrder...),
		}

		// Free session memory
		ma.stats.CurrentMemoryBytes -= session.AllocatedBytes
		ma.stats.CompletedSessions++
		ma.totalTime += assemblyDuration
		if ma.stats.CompletedSessions > 0 {
			ma.stats.AvgAssemblyTime = ma.totalTime / time.Duration(ma.stats.CompletedSessions)
		}
		delete(ma.sessions, pkt.MessageID)

		if ma.onComplete != nil {
			ma.onComplete(completed)
		}

		return completed, nil
	}

	return nil, nil // More fragments needed
}

// reaperLoop runs periodically in the background to evict abandoned or stalled sessions.
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

// evictStaleSessions scans all active sessions and purges those that exceeded SessionTimeout.
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
}

// GetStats returns a snapshot of assembler health and telemetry.
func (ma *MessageAssembler) GetStats() AssemblerStats {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	s := ma.stats
	s.ActiveSessions = len(ma.sessions)
	return s
}

// GetActiveSessionsInfo returns summary information on currently open sessions.
func (ma *MessageAssembler) GetActiveSessionsInfo() []map[string]interface{} {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(ma.sessions))
	now := time.Now()
	for msgID, s := range ma.sessions {
		elapsed := now.Sub(s.LastActivityAt)
		remaining := ma.config.SessionTimeout - elapsed
		if remaining < 0 {
			remaining = 0
		}

		result = append(result, map[string]interface{}{
			"message_id":       msgID,
			"total_fragments":  s.TotalFragments,
			"received_count":   s.ReceivedCount,
			"allocated_bytes":  s.AllocatedBytes,
			"age_seconds":      elapsed.Seconds(),
			"ttl_remaining_ms": remaining.Milliseconds(),
		})
	}
	return result
}
