package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/cfcp/protocol/pkg/client"
	"github.com/cfcp/protocol/pkg/porthopper"
)

const (
	TunnelCmdConnect byte = 0x01
	TunnelCmdData    byte = 0x02
	TunnelCmdClose   byte = 0x03
)

// TunnelMessage wraps application data transferred via CFCP datagrams.
// Format:
// [0]     Command (Connect=1, Data=2, Close=3)
// [1:9]   StreamID (uint64)
// [9:11]  DestAddrLen (uint16)
// [11:11+DestAddrLen] DestAddr string
// [11+DestAddrLen:] Payload data
type TunnelMessage struct {
	Command  byte
	StreamID uint64
	DestAddr string
	Payload  []byte
}

func (m *TunnelMessage) Marshal() []byte {
	destBytes := []byte(m.DestAddr)
	buf := make([]byte, 1+8+2+len(destBytes)+len(m.Payload))
	buf[0] = m.Command
	binary.BigEndian.PutUint64(buf[1:9], m.StreamID)
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(destBytes)))
	copy(buf[11:11+len(destBytes)], destBytes)
	copy(buf[11+len(destBytes):], m.Payload)
	return buf
}

func UnmarshalTunnelMessage(data []byte) (*TunnelMessage, error) {
	if len(data) < 11 {
		return nil, errors.New("tunnel: message too short")
	}
	cmd := data[0]
	streamID := binary.BigEndian.Uint64(data[1:9])
	destLen := int(binary.BigEndian.Uint16(data[9:11]))
	if len(data) < 11+destLen {
		return nil, errors.New("tunnel: corrupt destination address")
	}
	destAddr := string(data[11 : 11+destLen])
	payload := data[11+destLen:]

	return &TunnelMessage{
		Command:  cmd,
		StreamID: streamID,
		DestAddr: destAddr,
		Payload:  payload,
	}, nil
}

// TunnelClient connects local SOCKS5 to the remote CFCP proxy server.
type TunnelClient struct {
	hopper     *porthopper.PortHopper
	cfcpClient *client.Client
	streams    map[uint64]net.Conn
	mu         sync.RWMutex
	streamSeq  uint64
	serverHost string
}

func NewTunnelClient(hopper *porthopper.PortHopper, cfcpCli *client.Client, serverHost string) *TunnelClient {
	return &TunnelClient{
		hopper:     hopper,
		cfcpClient: cfcpCli,
		streams:    make(map[uint64]net.Conn),
		serverHost: serverHost,
	}
}

// HandleSocksConn proxies a single SOCKS5 connection through CFCP.
func (tc *TunnelClient) HandleSocksConn(conn net.Conn) {
	defer conn.Close()

	req, err := Handshake(conn)
	if err != nil {
		return
	}

	streamID := atomic.AddUint64(&tc.streamSeq, 1)
	tc.mu.Lock()
	tc.streams[streamID] = conn
	tc.mu.Unlock()

	defer func() {
		tc.mu.Lock()
		delete(tc.streams, streamID)
		tc.mu.Unlock()

		// Send close command
		closeMsg := &TunnelMessage{
			Command:  TunnelCmdClose,
			StreamID: streamID,
		}
		_, _, _ = tc.cfcpClient.SendMessage(closeMsg.Marshal())
	}()

	// Send Connect command to remote CFCP proxy
	connectMsg := &TunnelMessage{
		Command:  TunnelCmdConnect,
		StreamID: streamID,
		DestAddr: req.DestAddr,
	}

	_, _, err = tc.cfcpClient.SendMessage(connectMsg.Marshal())
	if err != nil {
		_ = SendReply(conn, RepFail)
		return
	}

	// Tell local client that SOCKS5 connection succeeded
	if err := SendReply(conn, RepSuccess); err != nil {
		return
	}

	// Stream reader: read data from local app, send via CFCP fragments
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			dataMsg := &TunnelMessage{
				Command:  TunnelCmdData,
				StreamID: streamID,
				Payload:  buf[:n],
			}
			_, _, sendErr := tc.cfcpClient.SendMessage(dataMsg.Marshal())
			if sendErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			return
		}
	}
}

// DispatchInboundData delivers assembled reverse proxy datagrams back to the local TCP connection.
func (tc *TunnelClient) DispatchInboundData(msg *TunnelMessage) {
	tc.mu.RLock()
	conn, exists := tc.streams[msg.StreamID]
	tc.mu.RUnlock()

	if !exists || conn == nil {
		return
	}

	if msg.Command == TunnelCmdData && len(msg.Payload) > 0 {
		_, _ = conn.Write(msg.Payload)
	} else if msg.Command == TunnelCmdClose {
		_ = conn.Close()
	}
}
