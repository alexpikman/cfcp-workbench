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

	"github.com/cfcp/protocol/pkg/client"
	"github.com/cfcp/protocol/pkg/porthopper"
	"github.com/cfcp/protocol/pkg/proxy"
)

const defaultHexPSK = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 proxy listen address")
	serverHost := flag.String("server", "127.0.0.1", "Remote CFCP proxy server IP or hostname")
	pskHex := flag.String("psk", defaultHexPSK, "32-byte Pre-Shared Key in Hex format")
	hopMode := flag.String("hop-mode", "dynamic_hopping", "Port defense mode: dynamic_hopping | masquerade_quic | masquerade_webrtc | fixed_port")
	minPort := flag.Int("min-port", 20000, "Port hopping range minimum")
	maxPort := flag.Int("max-port", 40000, "Port hopping range maximum")
	hopInterval := flag.Int("hop-interval", 5, "Port hopping interval in seconds")
	mtu := flag.Int("mtu", 256, "CFCP fragment payload MTU")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be a 64-character hexadecimal string (32 bytes)")
	}

	hopperCfg := porthopper.Config{
		Mode:           porthopper.Mode(*hopMode),
		PSK:            psk,
		MinPort:        *minPort,
		MaxPort:        *maxPort,
		DefaultPort:    9099,
		WindowDuration: time.Duration(*hopInterval) * time.Second,
	}

	hopper, err := porthopper.NewPortHopper(hopperCfg)
	if err != nil {
		log.Fatalf("Failed to initialize PortHopper: %v", err)
	}

	// Calculate initial hopping port
	currentPort := hopper.GetPort(time.Now(), 0)
	targetAddr := fmt.Sprintf("%s:%d", *serverHost, currentPort)

	fmt.Println("=================================================================")
	fmt.Println("    CFCP Stealth SOCKS5 Proxy Client (DPI Evasion & Hopping)     ")
	fmt.Println("=================================================================")
	fmt.Printf(" [LOCAL]  SOCKS5 Endpoint   : %s\n", *socksAddr)
	fmt.Printf(" [EGRESS] Target Server     : %s\n", *serverHost)
	fmt.Printf(" [CRYPTO] AEAD Encryption   : ChaCha20-Poly1305 (256-bit PSK)\n")
	fmt.Printf(" [DEFENSE] Port Hopping     : Mode: %s | Range: [%d-%d]\n", *hopMode, *minPort, *maxPort)
	fmt.Printf(" [DEFENSE] Active Port Now  : %d (Rotates every %ds)\n", currentPort, *hopInterval)
	fmt.Println("=================================================================")

	cfcpClient, err := client.NewClient(client.ClientConfig{
		ServerAddr:  targetAddr,
		PSK:         psk,
		FragmentMTU: *mtu,
		ACKTimeout:  4 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to initialize CFCP client: %v", err)
	}
	defer cfcpClient.Close()

	tunnel := proxy.NewTunnelClient(hopper, cfcpClient, *serverHost)

	// Start local SOCKS5 TCP listener
	listener, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("Failed to bind SOCKS5 listener on %s: %v", *socksAddr, err)
	}
	defer listener.Close()

	fmt.Printf("SOCKS5 Proxy ready! Configure your browser or apps to use socks5://%s\n", *socksAddr)

	// Port hop ticker that keeps target UDP port dynamically synchronized
	go func() {
		ticker := time.NewTicker(time.Duration(*hopInterval) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			newPort := hopper.GetPort(time.Now(), 0)
			fmt.Printf(" \033[36m[PORT-HOP]\033[0m Rotated UDP egress port -> \033[32m:%d\033[0m\n", newPort)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down SOCKS5 proxy client...")
		_ = listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-sigChan:
				return
			default:
				continue
			}
		}

		go tunnel.HandleSocksConn(conn)
	}
}
