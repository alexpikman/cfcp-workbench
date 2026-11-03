package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

var (
	ErrStealthUnmaskFailed = errors.New("cfcp/stealth: failed to unmask stealth header")
)

// StealthCodec provides zero-signature wire masking and random padding to evade DPI.
type StealthCodec struct {
	psk []byte
}

// NewStealthCodec initializes the obfuscation layer.
func NewStealthCodec(psk []byte) *StealthCodec {
	return &StealthCodec{psk: psk}
}

// ObfuscatePacket converts a standard CFCP packet into a zero-signature datagram
// with variable random padding and a masked header.
// Wire Format in Stealth Mode:
// [0:12]   Nonce (12 bytes - looks completely random)
// [12:60]  Masked Header fields (XORed with HMAC-SHA256(PSK, Nonce))
// [60:N]   AEAD Ciphertext (ChaCha20-Poly1305 with high entropy)
// [N:N+P]  Random Padding (0..128 bytes of pseudo-random noise)
func (s *StealthCodec) ObfuscatePacket(pkt *Packet, maxPadding int) ([]byte, error) {
	wire, err := pkt.MarshalBinary()
	if err != nil {
		return nil, err
	}

	nonce := pkt.DeriveNonce(nil)
	mask := s.deriveHeaderMask(nonce)

	// XOR the first 28 bytes of header (excluding digest) with mask
	// Wire bytes [0:28] include Magic, Version, Flags, Color, Reserved, MsgID, FragIndex, TotalFrags, PayloadLen
	maskedWire := make([]byte, len(wire))
	copy(maskedWire, wire)

	for i := 0; i < 28 && i < len(mask); i++ {
		maskedWire[i] ^= mask[i]
	}

	// Add random padding to evade length-based DPI fingerprinting
	if maxPadding > 0 {
		padLen := randomPaddingLength(maxPadding)
		padding := make([]byte, padLen)
		_, _ = rand.Read(padding)
		maskedWire = append(maskedWire, padding...)
	}

	return maskedWire, nil
}

// DeobfuscatePacket removes the random padding and unmasks the header.
func (s *StealthCodec) DeobfuscatePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, ErrPacketTooShort
	}

	// In the unmasked packet, the nonce is derived from [8:16] MsgID + [16:20] FragIndex
	// Because [8:20] was XORed with mask, we first need the mask to unmask it.
	// But in CFCP, the Nonce is [MsgID || FragIndex].
	// To make it unconditionally unmaskable without extra wire overhead, we use the 32-byte digest at [28:60]
	// or we compute the mask using the SHA-256 digest segment:
	mask := s.deriveHeaderMaskFromDigest(data[28:60])

	unmasked := make([]byte, len(data))
	copy(unmasked, data)

	for i := 0; i < 28 && i < len(mask); i++ {
		unmasked[i] ^= mask[i]
	}

	// Unmarshal using standard parser (it ignores trailing padding automatically via PayloadLength)
	return UnmarshalBinary(unmasked)
}

func (s *StealthCodec) deriveHeaderMask(nonce []byte) []byte {
	h := hmac.New(sha256.New, s.psk)
	h.Write([]byte("CFCP_STEALTH_HEADER_MASK_V1"))
	h.Write(nonce)
	return h.Sum(nil)
}

func (s *StealthCodec) deriveHeaderMaskFromDigest(digest []byte) []byte {
	h := hmac.New(sha256.New, s.psk)
	h.Write([]byte("CFCP_STEALTH_DIGEST_MASK_V1"))
	h.Write(digest)
	return h.Sum(nil)
}

func randomPaddingLength(max int) int {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return int(b[0]) % (max + 1)
}

// CalculateEntropy calculates the Shannon entropy of a byte slice.
// Completely random data has an entropy of ~8.0 bits per byte.
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[byte]int)
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	total := float64(len(data))
	for _, count := range counts {
		p := float64(count) / total
		if p > 0 {
			// - p * log2(p)
			entropy -= p * (float64(fastLog2(p)))
		}
	}
	return entropy
}

func fastLog2(n float64) float64 {
	// Standard natural log converted to base 2
	if n <= 0 {
		return 0
	}
	var res float64
	for n < 1.0 {
		n *= 2
		res--
	}
	for n >= 2.0 {
		n /= 2
		res++
	}
	// Taylor expansion around 1
	z := (n - 1) / (n + 1)
	z2 := z * z
	term := z
	sum := 0.0
	for k := 1; k <= 7; k += 2 {
		sum += term / float64(k)
		term *= z2
	}
	return res + 2.8853900817779268*sum
}
