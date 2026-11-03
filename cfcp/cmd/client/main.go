package main

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
	msgText := flag.String("msg", "Color-Fragmented Cascade Protocol datagram payload with ChaCha20-Poly1305 AEAD and SHA-256 integrity control.", "Message content to send")
	filePath := flag.String("file", "", "Optional path to binary file to transmit")
	mtu := flag.Int("mtu", 256, "Fragment payload chunk size in bytes (simulates fragmentation)")
	lossRate := flag.Int("loss", 0, "Artificial packet loss percentage (0-100)")
	dupRate := flag.Int("dup", 0, "Artificial packet duplicate percentage (0-100)")
	jitterMs := flag.Int("jitter", 0, "Max random jitter in milliseconds")
	shuffle := flag.Bool("shuffle", true, "Shuffle fragments to simulate out-of-order UDP arrival")
	flag.Parse()

	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		log.Fatalf("Invalid PSK: must be 64-character hexadecimal string")
	}

	var payload []byte
	if *filePath != "" {
		data, err := os.ReadFile(*filePath)
		if err != nil {
			log.Fatalf("Failed to read file %s: %v", *filePath, err)
		}
		payload = data
	} else {
		payload = []byte(*msgText)
	}

	fmt.Println("=================================================================")
	fmt.Println("       CFCP Client (Color-Fragmented Cascade Protocol)           ")
	fmt.Println("=================================================================")
	fmt.Printf(" [TARGET] Server Address  : %s\n", *serverAddr)
	fmt.Printf(" [PAYLOAD] Message Size   : %d bytes\n", len(payload))
	fmt.Printf(" [PARAM] Fragment Chunk   : %d bytes per fragment\n", *mtu)
	fmt.Printf(" [FAULT] Packet Loss Rate : %d%%\n", *lossRate)
	fmt.Printf(" [FAULT] Duplicate Rate   : %d%%\n", *dupRate)
	fmt.Printf(" [FAULT] Jitter Delay     : %d ms max\n", *jitterMs)
	fmt.Printf(" [FAULT] Out-of-Order     : %v\n", *shuffle)
	fmt.Println("-----------------------------------------------------------------")

	cfg := client.ClientConfig{
		ServerAddr:  *serverAddr,
		PSK:         psk,
		FragmentMTU: *mtu,
		ACKTimeout:  5 * time.Second,
		SimConfig: client.NetworkSimulationConfig{
			PacketLossPercent: *lossRate,
			DuplicatePercent:  *dupRate,
			MaxJitterDelay:    time.Duration(*jitterMs) * time.Millisecond,
			ShuffleFragments:  *shuffle,
		},
	}

	cli, err := client.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize CFCP client: %v", err)
	}
	defer cli.Close()

	fmt.Println("Encrypting with ChaCha20-Poly1305 and launching cascade datagrams...")

	msgID, rtt, err := cli.SendMessage(payload)
	if err != nil {
		fmt.Printf("\n \033[31m[FAILED]\033[0m Message transmission failed: %v\n", err)
		os.Exit(1)
	}

	stats := cli.GetStats()
	fmt.Printf("\n \033[32m[SUCCESS]\033[0m Message Delivered & Acknowledged by Server!\n")
	fmt.Printf("   Message ID        : 0x%016X\n", msgID)
	fmt.Printf("   Round-Trip Time   : %v\n", rtt)
	fmt.Printf("   Fragments Sent    : %d\n", stats.FragmentsSent)
	fmt.Printf("   Simulated Drops   : %d\n", stats.SimulatedDrops)
	fmt.Printf("   Duplicates Sent   : %d\n", stats.DuplicatesSent)
	fmt.Printf("   Total Wire Bytes  : %d bytes\n", stats.TotalBytesSent)
	fmt.Println("=================================================================")
}
