package proxy

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

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	RepSuccess = 0x00
	RepFail    = 0x01
)

var (
	ErrNotSocks5      = errors.New("socks5: unsupported protocol version (not SOCKS5)")
	ErrUnsupportedCmd = errors.New("socks5: unsupported command (only CONNECT supported)")
	ErrUnsupportedAtyp = errors.New("socks5: unsupported address type")
)

// Request represents a parsed client connection request.
type Request struct {
	DestAddr string // "host:port"
	Host     string
	Port     int
}

// Handshake performs the RFC 1928 SOCKS5 negotiation on a client connection.
func Handshake(conn net.Conn) (*Request, error) {
	// 1. Version and Authentication Method Selection
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read auth header error: %w", err)
	}

	if header[0] != Socks5Version {
		return nil, ErrNotSocks5
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("read methods error: %w", err)
	}

	// Select NO_AUTH
	if _, err := conn.Write([]byte{Socks5Version, AuthNone}); err != nil {
		return nil, fmt.Errorf("write auth response error: %w", err)
	}

	// 2. Client Connection Request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return nil, fmt.Errorf("read request header error: %w", err)
	}

	if reqHeader[0] != Socks5Version {
		return nil, ErrNotSocks5
	}
	if reqHeader[1] != CmdConnect {
		_ = SendReply(conn, RepFail)
		return nil, ErrUnsupportedCmd
	}

	atyp := reqHeader[3]
	var host string

	switch atyp {
	case AtypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return nil, err
		}
		host = net.IP(ipBuf).String()

	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return nil, err
		}
		host = string(domainBuf)

	case AtypIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return nil, err
		}
		host = net.IP(ipBuf).String()

	default:
		_ = SendReply(conn, RepFail)
		return nil, ErrUnsupportedAtyp
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	destAddr := net.JoinHostPort(host, strconv.Itoa(port))

	return &Request{
		DestAddr: destAddr,
		Host:     host,
		Port:     port,
	}, nil
}

// SendReply sends the SOCKS5 response back to the client.
func SendReply(conn net.Conn, repCode byte) error {
	// 0x05, repCode, 0x00 (RSV), 0x01 (IPv4), 0.0.0.0, port 0
	reply := []byte{Socks5Version, repCode, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}
