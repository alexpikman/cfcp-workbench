package protocol_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/cfcp/protocol/pkg/assembler"
	"github.com/cfcp/protocol/pkg/crypto"
	"github.com/cfcp/protocol/pkg/protocol"
)

// TestWirePacketSerialization verifies that binary packing and unpacking preserves all fields.
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

	if len(wire) != protocol.HeaderSize+len(orig.Payload) {
		t.Fatalf("expected wire len %d, got %d", protocol.HeaderSize+len(orig.Payload), len(wire))
	}

	parsed, err := protocol.UnmarshalBinary(wire)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if parsed.MessageID != orig.MessageID {
		t.Errorf("MessageID mismatch: expected %x, got %x", orig.MessageID, parsed.MessageID)
	}
	if parsed.FragmentIndex != orig.FragmentIndex {
		t.Errorf("FragmentIndex mismatch: expected %d, got %d", orig.FragmentIndex, parsed.FragmentIndex)
	}
	if parsed.TotalFragments != orig.TotalFragments {
		t.Errorf("TotalFragments mismatch: expected %d, got %d", orig.TotalFragments, parsed.TotalFragments)
	}
	if !bytes.Equal(parsed.Payload, orig.Payload) {
		t.Errorf("Payload mismatch: expected %q, got %q", orig.Payload, parsed.Payload)
	}
	if !bytes.Equal(parsed.MessageDigest[:], orig.MessageDigest[:]) {
		t.Errorf("Digest mismatch")
	}
}

// TestChaCha20Poly1305AEAD tests encryption, decryption, and authentication failure on tampered data.
func TestChaCha20Poly1305AEAD(t *testing.T) {
	key, err := crypto.GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey failed: %v", err)
	}

	cipher, err := crypto.NewAEADCipher(key)
	if err != nil {
		t.Fatalf("NewAEADCipher failed: %v", err)
	}

	msgID := uint64(987654321)
	fragIdx := uint32(2)
	plaintext := []byte("Sensitive protocol payload that must be protected in flight")
	aad := []byte("HeaderMetadataBinding")

	ciphertext := cipher.EncryptFragment(msgID, fragIdx, plaintext, aad)
	if len(ciphertext) != len(plaintext)+crypto.TagSize {
		t.Fatalf("ciphertext len expected %d, got %d", len(plaintext)+crypto.TagSize, len(ciphertext))
	}

	// Decrypt valid
	decrypted, err := cipher.DecryptFragment(msgID, fragIdx, ciphertext, aad)
	if err != nil {
		t.Fatalf("valid decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: expected %q, got %q", plaintext, decrypted)
	}

	// Tamper with ciphertext byte
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[0] ^= 0xFF

	_, err = cipher.DecryptFragment(msgID, fragIdx, tamperedCiphertext, aad)
	if err == nil {
		t.Fatalf("expected error on tampered ciphertext, got nil")
	}

	// Tamper with AAD (header)
	tamperedAAD := []byte("TamperedHeaderBinding")
	_, err = cipher.DecryptFragment(msgID, fragIdx, ciphertext, tamperedAAD)
	if err == nil {
		t.Fatalf("expected error on tampered AAD, got nil")
	}
}

// TestOutOfOrderReassemblyAndIntegrity tests that out-of-order delivery is assembled and SHA-256 verified.
func TestOutOfOrderReassemblyAndIntegrity(t *testing.T) {
	key, _ := crypto.GenerateRandomKey()
	cipher, _ := crypto.NewAEADCipher(key)

	cfg := assembler.AssemblerConfig{
		SessionTimeout:        5 * time.Second,
		CleanupInterval:       500 * time.Millisecond,
		MaxConcurrentSessions: 10,
		MaxSessionMemoryBytes: 1024 * 1024,
		MaxTotalMemoryBytes:   10 * 1024 * 1024,
	}
	asm := assembler.NewMessageAssembler(cfg, cipher)
	defer asm.Close()

	payload := []byte("Hello CFCP! This message is split into 4 parts and delivered in reverse order.")
	digest := crypto.ComputeMessageDigest(payload)
	msgID := uint64(0xABCDEF0123456789)

	chunks := [][]byte{
		payload[0:20],
		payload[20:40],
		payload[40:60],
		payload[60:],
	}
	total := uint32(len(chunks))

	packets := make([]*protocol.Packet, total)
	for i := uint32(0); i < total; i++ {
		pkt := &protocol.Packet{
			Version:        protocol.ProtocolVersion,
			Flags:          protocol.FlagData | protocol.FlagEncrypted,
			Color:          protocol.ColorTag(i % 7),
			MessageID:      msgID,
			FragmentIndex:  i,
			TotalFragments: total,
			MessageDigest:  digest,
		}
		aad := pkt.HeaderAAD()
		pkt.Payload = cipher.EncryptFragment(msgID, i, chunks[i], aad)
		pkt.PayloadLength = uint32(len(pkt.Payload))
		packets[i] = pkt
	}

	// Feed packets in reverse out-of-order sequence: [3, 1, 0, 2]
	deliveryOrder := []int{3, 1, 0, 2}
	var completed *assembler.CompletedMessage

	for _, idx := range deliveryOrder {
		res, procErr := asm.ProcessPacket(packets[idx])
		if procErr != nil {
			t.Fatalf("unexpected process error on fragment %d: %v", idx, procErr)
		}
		if res != nil {
			completed = res
		}
	}

	if completed == nil {
		t.Fatalf("expected message to be assembled, got nil")
	}

	if !bytes.Equal(completed.Payload, payload) {
		t.Fatalf("assembled payload mismatch: expected %q, got %q", payload, completed.Payload)
	}

	if !bytes.Equal(completed.Digest[:], digest[:]) {
		t.Fatalf("digest mismatch")
	}
}

// TestCorruptedHashRejection verifies that SHA-256 digest mismatch is rejected before release.
func TestCorruptedHashRejection(t *testing.T) {
	key, _ := crypto.GenerateRandomKey()
	cipher, _ := crypto.NewAEADCipher(key)

	cfg := assembler.DefaultConfig()
	asm := assembler.NewMessageAssembler(cfg, cipher)
	defer asm.Close()

	payload := []byte("Integrity protected message block")
	wrongDigest := crypto.ComputeMessageDigest([]byte("Forged payload different text"))
	msgID := uint64(55555)

	pkt := &protocol.Packet{
		Version:        protocol.ProtocolVersion,
		Flags:          protocol.FlagData | protocol.FlagEncrypted,
		Color:          protocol.ColorGreen,
		MessageID:      msgID,
		FragmentIndex:  0,
		TotalFragments: 1,
		MessageDigest:  wrongDigest, // mismatched digest!
	}
	aad := pkt.HeaderAAD()
	pkt.Payload = cipher.EncryptFragment(msgID, 0, payload, aad)
	pkt.PayloadLength = uint32(len(pkt.Payload))

	_, err := asm.ProcessPacket(pkt)
	if err == nil {
		t.Fatalf("expected integrity hash mismatch error, got nil")
	}
}

// TestAntiDoSSessionTimeout verifies that incomplete sessions are evicted from memory by the reaper.
func TestAntiDoSSessionTimeout(t *testing.T) {
	key, _ := crypto.GenerateRandomKey()
	cipher, _ := crypto.NewAEADCipher(key)

	cfg := assembler.AssemblerConfig{
		SessionTimeout:        200 * time.Millisecond,
		CleanupInterval:       50 * time.Millisecond,
		MaxConcurrentSessions: 10,
		MaxSessionMemoryBytes: 1024,
		MaxTotalMemoryBytes:   10240,
	}
	asm := assembler.NewMessageAssembler(cfg, cipher)
	defer asm.Close()

	evicted := make(chan uint64, 1)
	asm.SetCallbacks(nil, func(msgID uint64, reason string) {
		evicted <- msgID
	})

	// Send 1 of 2 fragments, then stall
	msgID := uint64(99999)
	dummyBytes := make([]byte, 32)
	rand.Read(dummyBytes)
	digest := crypto.ComputeMessageDigest(dummyBytes)

	pkt := &protocol.Packet{
		Version:        protocol.ProtocolVersion,
		Flags:          protocol.FlagData | protocol.FlagEncrypted,
		Color:          protocol.ColorPurple,
		MessageID:      msgID,
		FragmentIndex:  0,
		TotalFragments: 2,
		MessageDigest:  digest,
	}
	aad := pkt.HeaderAAD()
	pkt.Payload = cipher.EncryptFragment(msgID, 0, []byte("part1"), aad)
	pkt.PayloadLength = uint32(len(pkt.Payload))

	_, err := asm.ProcessPacket(pkt)
	if err != nil {
		t.Fatalf("failed to insert initial fragment: %v", err)
	}

	stats := asm.GetStats()
	if stats.ActiveSessions != 1 {
		t.Fatalf("expected 1 active session, got %d", stats.ActiveSessions)
	}

	// Wait for reaper eviction
	select {
	case evictedID := <-evicted:
		if evictedID != msgID {
			t.Errorf("expected evicted ID %d, got %d", msgID, evictedID)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for Anti-DoS session eviction")
	}

	statsAfter := asm.GetStats()
	if statsAfter.ActiveSessions != 0 {
		t.Errorf("expected 0 active sessions after timeout eviction, got %d", statsAfter.ActiveSessions)
	}
	if statsAfter.TimedOutSessions != 1 {
		t.Errorf("expected 1 timed out session recorded in stats, got %d", statsAfter.TimedOutSessions)
	}
}
