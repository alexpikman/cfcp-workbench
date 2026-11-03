# CFCP: Color-Fragmented Cascade Protocol

**CFCP (Color-Fragmented Cascade Protocol)** is a secure, high-throughput transport protocol operating over **UDP**. It is engineered to overcome classic TCP constraints—such as Head-of-Line (HoL) blocking and rigid in-order delivery—by fragmenting messages into color-tagged cascade units that can arrive in arbitrary sequence and assemble with cryptographic integrity.

---

## Key Modules & Capabilities

### 1. Cryptographic AEAD Layer (ChaCha20-Poly1305)
- **Algorithm**: RFC 8439 `ChaCha20-Poly1305` authenticated encryption with 256-bit Pre-Shared Key (PSK).
- **Zero-Overhead Nonce Derivation**: A 96-bit unique nonce is deterministically computed as:
  ```
  Nonce = [ MessageID (8 bytes, uint64 BigEndian) || FragmentIndex (4 bytes, uint32 BigEndian) ]
  ```
- **Header Authentication (AAD)**: Ties packet metadata to the Poly1305 tag.

### 2. Stealth Proxy & Port Defense (DPI & Tracking Evasion)
- **Local SOCKS5 Server (`127.0.0.1:1080`)**: Intercepts browser and system TCP/UDP streams and converts them into out-of-order CFCP cascade datagrams.
- **Dynamic Port Hopping**: Rotates UDP egress and ingress ports dynamically across a port range (e.g., 20000–40000) using a shared HMAC-SHA256 PRNG sequence keyed with the PSK. Intermediate DPI censors cannot track a fixed port.
- **Port Masquerading**: Configurable to camouflage as ubiquitous port 443 (QUIC / HTTP3) or port 3478 (WebRTC STUN/TURN video calls).
- **Zero-Signature Header Obfuscation**: Removes cleartext magic signatures ("CFCP") and masks headers with a keystream mask. Datagrams exhibit $\sim 7.99$ bits/byte Shannon entropy (indistinguishable from white noise).
- **Traffic Padding**: Appends random 0–128 byte dummy padding to defeat packet length fingerprinting.

### 3. Anti-DoS Buffer & Memory Protection
- **Sliding Session Eviction**: Unfinished, stalled, or forged sessions are purged from server RAM after an eviction timeout (default 5–10 seconds).
- **Background Active Reaper**: A dedicated reaper goroutine runs on a sub-second ticker to actively reclaim memory rather than waiting for next access.
- **Resource Quotas**:
  - `MaxConcurrentSessions`: Hard limit on simultaneous active sessions (e.g. 1024).
  - `MaxSessionMemoryBytes`: Per-message memory ceiling (e.g. 4 MB).
  - `MaxTotalMemoryBytes`: Global memory cap across all sessions (e.g. 64 MB).
- **Duplicate Suppression**: Duplicate datagrams are recognized and safely dropped without causing memory allocation.

### 3. Whole-Message Integrity Control (SHA-256)
- The sender computes a full 32-byte SHA-256 hash of the complete message prior to fragmentation.
- The hash is transmitted in the authenticated packet header.
- The server `MessageAssembler` validates the computed SHA-256 hash against the glued plaintext **before** releasing the message to the application layer.

### 4. Interactive CLI & Structured Telemetry
- Client and server display real-time metrics:
  - Total transmitted fragments and arrival sequence
  - Network loss % and dropped packets
  - Duplicate packets detected and dropped
  - Assembly duration (microsecond/millisecond precision)
  - Active sessions and allocated memory (KB/MB)

---

## Wire Format (60 Bytes Fixed Header + Ciphertext)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Magic "CFCP" (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Flags     |   ColorTag    |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Message ID (Bytes 0-3)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Message ID (Bytes 4-7)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Fragment Index (uint32)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Total Fragments (uint32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload Length (uint32)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Message SHA-256 Digest                      +
|                         (32 bytes)                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Encrypted Payload (ChaCha20 Ciphertext + 16B Poly1305 MAC) |
|                         ... variable ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## Quickstart & Commands

### 1. Run Unit Tests
```bash
cd cfcp
go test -v ./pkg/protocol/...
```

### 2. Start UDP Server
```bash
go run ./cmd/server/main.go -addr 0.0.0.0:9099 -timeout 6
```

### 3. Run Client with Simulated Faults
```bash
# Send text with out-of-order shuffling and 256B chunk MTU
go run ./cmd/client/main.go -addr 127.0.0.1:9099 -msg "Testing CFCP Cascade UDP" -mtu 256 -shuffle=true

# Simulate 10% packet loss and 15% duplicate delivery
go run ./cmd/client/main.go -addr 127.0.0.1:9099 -loss 10 -dup 15 -mtu 128
```
