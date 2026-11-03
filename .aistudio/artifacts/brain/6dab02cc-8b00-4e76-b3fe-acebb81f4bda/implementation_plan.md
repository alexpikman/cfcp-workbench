# CFCP (Color-Fragmented Cascade Protocol) — Go Implementation & Visual Protocol Workbench

This specification outlines the architecture, cryptographic security layer, Anti-DoS memory management, and interactive simulator for the **CFCP (Color-Fragmented Cascade Protocol)**, delivering resilient, out-of-order datagram transmission over UDP with ChaCha20-Poly1305 AEAD, SHA-256 integrity checks, and real-time telemetry.

***

### User Review & Critical Decisions

> [!IMPORTANT]
> The following requirements were confirmed during the interactive interview:
> - **AEAD Cipher**: ChaCha20-Poly1305 for high-performance software execution on UDP without requiring dedicated AES-NI hardware.
> - **Key & Nonce Management**: 256-bit Pre-Shared Key (PSK) with deterministic 96-bit per-fragment nonces derived from `MessageID (64-bit)` + `FragmentIndex (32-bit)` to guarantee mathematical uniqueness without payload nonce overhead.
> - **Delivery Format**: Complete modular Go codebase (with CLI binaries, unit tests, and benchmarks) coupled with an interactive web-based protocol simulator and developer workbench.

***

### 1. Overview & Core Concept

**CFCP (Color-Fragmented Cascade Protocol)** is a UDP-based transport protocol designed for scenarios where TCP head-of-line blocking and strict sequential ordering hinder throughput and resilience under jitter or loss. CFCP treats data as discrete, "color-tagged" cascade fragments that can be transmitted, routed, and assembled in arbitrary order.

- **Target Audience**: Systems engineers, network protocol designers, distributed systems developers, and real-time game/media network engineers.
- **Core Value**:
  - Independent out-of-order delivery with cascade assembly.
  - End-to-end cryptographic confidentiality and tamper-proofing via ChaCha20-Poly1305 AEAD.
  - Memory-safe, DoS-resistant session assembler that bounds memory usage and automatically reclaims abandoned sessions.
  - Full cryptographic verification with SHA-256 message digests before payload materialization.

***

### 2. User Experience & Visual Design

The web application provides an enterprise-grade developer workbench adhering to SaaS telemetry standards (clean 1-line top bar, high-density data grids, tabular numerals, and zero-pill typography):

- **Workbench Layout**:
  - **Top Bar**: Wordmark `CFCP Transport Engine`, tab navigation (`Live Protocol Simulator`, `Go Architecture & Code Explorer`, `Network Benchmark & Stress Test`), and action buttons (`Trigger Transfer`, `Reset Session`).
  - **Simulation Console**:
    - **Transmission Controller**: Payload input (text/JSON/file mock), fragment MTU size slider (256B–1400B), artificial network degradation controls (packet loss 0–50%, duplicate rate 0–30%, jitter/reordering delay 10–200ms, and server Anti-DoS eviction timeout 2–15s).
    - **Cascade Pipeline Visualizer**: Interactive visual flow showing (1) Plaintext Payload $\to$ (2) SHA-256 Hash Generation $\to$ (3) Fragmentation & Color-tagging $\to$ (4) ChaCha20-Poly1305 AEAD Encryption $\to$ (5) Simulated UDP Flight with out-of-order shuffling $\to$ (6) Server Assembly Buffer & Anti-DoS countdown $\to$ (7) Integrity Hash Verification & Decryption.
    - **Telemetry & Diagnostics**: Tabular numerals displaying total transmitted fragments, received count, duplicate drops, retransmission requests, assembly duration ($\mu$s/ms), effective throughput, and buffer memory load.
  - **Go Code Viewer & Export Hub**: Interactive syntax-highlighted browser for all modular Go source files with 1-click copy and file download.

***

### 3. Key Product Decisions & Trade-Offs

- **AEAD Nonce Construction**:
  - *Chosen Approach*: 96-bit synthetic nonce `[MessageID: 8 bytes][FragmentIndex: 4 bytes]`.
  - *Why*: Eliminates 12 bytes of wire overhead per UDP datagram while mathematically preventing nonce reuse for a given session.
  - *Alternatives Considered*: Random 12-byte nonce prepended to each fragment (adds 12B wire overhead per packet and requires CSPRNG invocation per fragment).
- **Anti-DoS Memory Strategy**:
  - *Chosen Approach*: Sliding expiry timer with active background reaper goroutine (`time.Ticker`) + strict max concurrent active sessions quota + bounded memory cap per message.
  - *Why*: Prevents memory exhaustion attacks where adversaries flood fragmented headers with different Message IDs without completing transfers.
  - *Alternatives Considered*: Passive eviction upon access (leaves abandoned sessions indefinitely in memory).
- **Integrity Validation (SHA-256)**:
  - *Chosen Approach*: Message-level SHA-256 digest placed in authenticated fragment metadata and verified after all fragments are authenticated and decrypted.
  - *Why*: Poly1305 validates per-fragment integrity, while SHA-256 validates the reconstructed whole-message semantic integrity.

***

### 4. Technical Architecture & Data Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CFCP Architecture Flow                            │
└─────────────────────────────────────────────────────────────────────────────┘

  Client Application Payload
              │
              ▼
  [SHA-256 Message Digest Calculation]
              │
              ▼
  [Cascade Slicer: N Fragments (Color-tagged ID + Seq + Total)]
              │
              ▼
  [ChaCha20-Poly1305 AEAD Encryption] (Nonce: MsgID || Seq)
              │
              ▼
  [UDP Datagram Flight] ──── (Loss, Jitter, Duplicates, Reordering)
              │
              ▼
  [UDP Server Listener]
              │
              ▼
  [MessageAssembler (Anti-DoS Protected)]
    ├── Active Sessions Table (Protected by sync.RWMutex)
    ├── Memory Quota Check (Max 64MB overall, 4MB per session)
    ├── Eviction Reaper Goroutine (5s-10s timeout purge)
    ├── ChaCha20-Poly1305 AEAD Decryption
    └── Out-of-Order Slot Insertion & Duplicate Elimination
              │
              ▼ (When all fragments received)
  [SHA-256 Reconstructed Verification]
              │
         ┌────┴────┐
      Valid     Invalid
         │         │
         ▼         ▼
    [Emit ACK]  [Drop Session & Log Warning]
```

#### Go Codebase Structure
The project will provide a clean, production-grade Go module `cfcp`:
1. `pkg/protocol/packet.go`: Binary wire protocol format, header encoding/decoding, bitwise flags.
2. `pkg/crypto/aead.go`: ChaCha20-Poly1305 cipher wrapper, deterministic nonce generation, secure PSK handling.
3. `pkg/assembler/assembler.go`: Memory-bounded, thread-safe message assembler with eviction ticker, session states, and SHA-256 integrity verifier.
4. `pkg/client/client.go`: High-performance UDP sender with packet loss simulation, retry loop, and out-of-order cascade emitter.
5. `pkg/server/server.go`: UDP server socket handler, ACK transmitter, and event hooks.
6. `cmd/server/main.go` & `cmd/client/main.go`: Interactive CLI applications with colorized ANSI telemetry, packet loss metrics, and live statistics.
7. `pkg/protocol/packet_test.go`: Unit tests for fragmentation, encryption, reassembly, corrupted hash rejection, and session timeout eviction.
