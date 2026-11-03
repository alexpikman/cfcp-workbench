package protocol

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

// Color definitions for cascade tags (used for multiplexing, QoS, or visualization)
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
	ErrPacketTooShort    = errors.New("cfcp: packet buffer is shorter than header size")
	ErrInvalidMagic      = errors.New("cfcp: invalid magic bytes in packet header")
	ErrUnsupportedVer    = errors.New("cfcp: unsupported protocol version")
	ErrPayloadMismatch   = errors.New("cfcp: payload length does not match header field")
	ErrInvalidFragmentNo = errors.New("cfcp: fragment index is greater than or equal to total fragments")
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

	// Magic
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

	// Verify magic bytes
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
// This ties the header fields directly to the cryptographic MAC tag,
// preventing intermediate nodes from tampering with MessageID, FragmentIndex,
// or TotalFragments without invalidating the Poly1305 authentication tag.
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

// DeriveNonce derives a 12-byte nonce for AEAD (ChaCha20-Poly1305 / AES-GCM).
// It modifies the baseNonce with the packet MessageID and FragmentIndex,
// guaranteeing a strictly unique nonce per datagram under the same secret key.
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
