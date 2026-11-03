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

// Default 256-bit PSK for testing: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const defaultHexPSK = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

func main() {
	listenAddr := flag.String("addr", "0.0.0.0:9099", "UDP listen address (host:port)")
	pskHex := flag.String("psk", defaultHexPSK, "32-byte Pre-Shared Key in Hex format")
	timeoutSec := flag.Int("timeout", 6, "Anti-DoS session timeout in seconds (default 6s)")
	cleanupSec := flag.Int("cleanup", 1, "Anti-DoS reaper cleanup interval in seconds")
	maxSessions := flag.Int("max-sessions", 1024, "Maximum concurrent active sessions")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be a 64-character hexadecimal string (32 bytes)")
	}

	fmt.Println("=================================================================")
	fmt.Println("       CFCP Server (Color-Fragmented Cascade Protocol)           ")
	fmt.Println("=================================================================")
	fmt.Printf(" [CONFIG] Listen Address : %s\n", *listenAddr)
	fmt.Printf(" [CONFIG] Crypto Engine  : ChaCha20-Poly1305 (AEAD)\n")
	fmt.Printf(" [CONFIG] Anti-DoS Time  : %ds session timeout, %ds reaper interval\n", *timeoutSec, *cleanupSec)
	fmt.Printf(" [CONFIG] Max Sessions   : %d\n", *maxSessions)
	fmt.Println("-----------------------------------------------------------------")

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

	// Register event callbacks
	srv.GetAssembler().SetCallbacks(
		func(msg *assembler.CompletedMessage) {
			// Telemetry hook
		},
		func(msgID uint64, reason string) {
			fmt.Printf(" \033[33m[! Anti-DoS Eviction]\033[0m MessageID 0x%016X purged: %s\n", msgID, reason)
		},
	)

	srv.OnMessage(func(msg *assembler.CompletedMessage, remoteAddr *net.UDPAddr) {
		preview := string(msg.Payload)
		if len(preview) > 60 {
			preview = preview[:57] + "..."
		}
		fmt.Printf(" \033[32m[✓ Message Assembled]\033[0m ID: 0x%016X | From: %s\n", msg.MessageID, remoteAddr.String())
		fmt.Printf("   Fragments: %d | Time: %v | Size: %d bytes\n", msg.TotalFragments, msg.AssemblyTime, len(msg.Payload))
		fmt.Printf("   SHA-256  : %x (Verified)\n", msg.Digest)
		fmt.Printf("   Arrival  : %v\n", msg.ArrivalOrder)
		fmt.Printf("   Payload  : %q\n", preview)
		fmt.Println("-----------------------------------------------------------------")
	})

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer srv.Stop()

	fmt.Printf("CFCP Server listening on UDP %s. Press Ctrl+C to shutdown.\n\n", *listenAddr)

	// Periodic stats printer
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-sigChan:
			fmt.Println("\nGracefully shutting down CFCP server...")
			return
		case <-ticker.C:
			srvStats, asmStats := srv.GetStats()
			fmt.Printf(" \033[36m[STATS]\033[0m Recv Packets: %d | Active Sessions: %d | Completed: %d | Timed Out: %d | Dups: %d | Memory: %d KB\n",
				srvStats.PacketsReceived,
				asmStats.ActiveSessions,
				asmStats.CompletedSessions,
				asmStats.TimedOutSessions,
				asmStats.DuplicatePackets,
				asmStats.CurrentMemoryBytes/1024,
			)
		}
	}
}
