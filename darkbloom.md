### Summary of DGInf/Darkbloom "App Attest-based Confidential Compute"

This paper describes DGInf, a decentralized AI inference network that runs on consumer Apple Silicon Macs. The core problem it solves: a user wants to run AI inference on someone else's Mac, but the Mac's owner — who has root access and physical custody — should not be able to see the prompts or responses being processed.

The architecture has three main components:

- Consumer: submits inference requests via an OpenAI-compatible API
- Coordinator: runs inside an Intel TDX hardware TEE in the cloud, routes requests, and verifies provider attestations
- Provider: a third-party Mac contributing compute, treated as adversarial

The central security technique is software access path elimination. Rather than encrypting memory, the system removes every software channel through which the machine's owner could observe inference data:

- The inference engine (MLX, loaded via PyO3) runs in-process inside a single hardened Rust binary — no subprocess, no localhost HTTP server, no IPC to intercept
- PT_DENY_ATTACH blocks debuggers like lldb and dtrace at the kernel level
- Hardened Runtime (without get-task-allow) blocks task_for_pid and mach_vm_read from external processes
- System Integrity Protection (SIP) enforces the above and, the authors prove formally (Theorem 1), cannot be disabled during a process's lifetime without rebooting — and rebooting kills the process

To defend against RDMA over Thunderbolt 5 (which can DMA-read host memory at 80 Gb/s), the system uses Apple's Hypervisor.framework to map inference memory into an empty VM. ARM Stage 2 page tables then hide this memory from RDMA at the hardware level, with reportedly 0% performance overhead.

Provider trustworthiness is established via a four-layer attestation stack: a Secure Enclave P-256 signature, MDM SecurityInfo queries (independently confirming SIP/Secure Boot status), Apple's Managed Device Attestation (an Apple-signed X.509 chain proving genuine hardware), and a 5-minute challenge-response loop verifying the security posture hasn't degraded.

The residual attack surface is reduced to physically desoldering LPDDR5x memory chips from the SoC package — the same threat model Apple accepts for Private Cloud Compute.

### Does It Implement Memory Encryption?

No, it does not implement memory encryption for inference data — and this is a deliberate design choice, not an oversight.

The paper is explicit about this. From Section 1: "Rather than encrypting memory (which Apple Silicon cannot do for third-party code), we eliminate every software mechanism through which the machine's owner could observe inference data." The comparison table in Section 12 lists "Memory encryption: None" for both DGInf and Apple's Private Cloud Compute.

The reason is a hardware limitation: Apple Silicon provides no TEE accessible to third-party applications. The Secure Enclave can sign and generate keys but cannot encrypt main system memory or run arbitrary isolated code. App Attest returns false on macOS. So memory encryption in the style of Intel TDX, AMD SEV-SNP, or NVIDIA Confidential Computing simply isn't available on this hardware.

The system does use cryptography in two adjacent places, which is worth distinguishing from memory encryption:

- End-to-end encryption of inference payloads in transit (Section 10): NaCl Box, using X25519 key agreement plus XSalsa20-Poly1305, with a fresh ephemeral key per request for forward secrecy. This protects data flowing between consumer and provider.
- AES-256 encryption of activations transferred between machines over RDMA (mentioned as future work in Section 17), measured at 42.5 GB/s.

But during actual inference computation, the model weights, prompts, KV cache, and activations sit in plaintext in unified memory. The security argument is that no software path exists for the owner to read that memory — not that the memory itself is encrypted. That's the core philosophical bet of the design: access path elimination as a substitute for memory encryption when the hardware can't provide the latter.

### Adversary models

_What are possible adversary models here, assuming we're using a Mac mini hardware device, and how much hardware or software penetration do we need to extract either inference payloads/results, *or* signing keys? Additionally, how are signing keys generated - is there a chain of trust that the App Attest key binds to?_

Good questions. Let me work through these carefully, because the paper's security model has different answers depending on which asset you're trying to extract.

### Adversary Models on a Mac mini

The paper formalizes one adversary (the malicious provider with root access), but in practice there's a spectrum. Let me lay out the realistic ones for Mac mini hardware specifically:

1. Root-level software adversary (the paper's primary model). The owner has admin access and runs arbitrary userspace code as root, but SIP is enabled and they haven't rebooted. This is what the paper is designed to defeat. Every standard memory inspection tool — lldb, dtrace, Instruments, task_for_pid, mach_vm_read, /dev/mem — is blocked by PT_DENY_ATTACH, Hardened Runtime, or simply doesn't exist on Apple Silicon.

2. Reboot-and-reconfigure adversary. The owner reboots into Recovery Mode, disables SIP via csrutil disable, then reboots back. The inference process is now dead and its memory wiped. To re-enter the network, they must re-attest — and the MDM SecurityInfo query will independently report SIP as disabled, so the coordinator rejects them. The 5-minute challenge-response also catches this. Mitigation cost to attacker: none works, because they can't re-join the network with weakened security.

3. RDMA-over-Thunderbolt adversary. With macOS 26.2+, the owner enables RDMA (which itself requires a Recovery OS boot) and connects a second Mac via Thunderbolt 5 to DMA-read host memory at 80 Gb/s. This bypasses every software protection. The paper's defense is the Hypervisor.framework Stage 2 page tables, which place inference memory at guest physical addresses invisible to RDMA's host physical address space. The coordinator enforces "if RDMA enabled, hypervisor must be active" via attestation.

4. Kernel zero-day adversary. The paper explicitly acknowledges this in Section 16. A SIP bypass, Hardened Runtime bypass, or KIP circumvention vulnerability would collapse the trust model. This is Assumption 1, and the paper offers no defense beyond "Apple patches quickly."

5. Physical adversary with non-destructive access. The Mac mini is interesting here because it's smaller and more accessible than other Macs. The attacker can open the case, attach probes to exposed buses, and try cold-boot attacks on RAM. But on Apple Silicon — and this is the key Mac mini fact — LPDDR5x memory is soldered directly into the SoC package itself, not onto the logic board as separate chips. There are no DRAM traces on the PCB to probe. Cold-boot attacks against socketed DIMMs don't apply.

6. Physical adversary with destructive access. Decapping the SoC, using focused ion beam to expose memory dies, or microprobing the in-package interconnect. This is the residual threat the paper accepts. It requires lab equipment (FIB workstations cost hundreds of thousands of dollars), destroys the device, and yields data only for the single in-flight inference at the moment of attack — model weights and activations of one request, not historical data.

7. Supply chain / firmware adversary. Compromising the device before delivery, or pushing malicious Secure Enclave firmware. The paper trusts Apple here (Assumption 2), and Apple's MDA certificate chain would still validate genuine hardware — but a compromised SepOS could in principle exfiltrate keys. This is outside the paper's threat model.

8. Apple itself. Trusted by assumption. Apple controls the MDA root CA, the Secure Enclave firmware, and the macOS kernel. There's no defense against a malicious Apple in this design — the same as PCC.

### What It Takes to Extract Each Asset

These are very different difficulty levels.

To extract an inference payload or response (in-flight):

- Software-only: requires a kernel zero-day that bypasses SIP or Hardened Runtime. Otherwise impossible by the paper's argument.
- Hardware non-destructive: enable RDMA via Recovery boot, connect a Thunderbolt 5 host, DMA-read host memory. Defeated by the hypervisor isolation if active. If hypervisor isn't active, the coordinator marks the provider untrusted and stops sending requests — so you can DMA all you want, but no real inference data flows to you.
- Hardware destructive: decap the SoC, microprobe the LPDDR5x in-package interconnect during a live inference. Lab-grade attack. Yields only the current in-flight request.

To extract the long-term Secure Enclave signing key:

This is dramatically harder. The P-256 signing key is generated inside the Secure Enclave and never leaves it. The dataRepresentation stored on disk is an opaque encrypted blob that only functions on the originating SE.

- Software-only: requires compromising the Secure Enclave itself, not just macOS. The SE runs SepOS on a separate ARM core with its own memory, communicating with the application processor via a mailbox interface. A macOS root compromise gives you the handle but not the key.
- Hardware non-destructive: not known to be feasible on current Apple Silicon. Past SE attacks (checkm8 era on A10/A11) required bootrom exploits that don't apply to M-series chips.
- Hardware destructive: decapping the SE region of the SoC and attempting to extract key material from the SE's dedicated secure storage. Even harder than extracting inference data because SE keys are stored with hardware-bound entanglement to a per-device UID fused at manufacture. You can't relocate them to another device even if extracted.

To extract the X25519 long-term encryption key:

The paper says this key is "stored on disk with restricted permissions (0600); its binding to the Secure Enclave identity is verified by the coordinator." This is weaker than the SE signing key — a root compromise gets you this file directly. However, the binding means a stolen X25519 key can't be transplanted to another machine and pass attestation, since the SE signing key (which the coordinator uses to verify the X25519 key's authenticity) stays on the original device. So you can decrypt requests routed to that specific device while the device is still trusted, but the moment a fresh attestation challenge fails — or the device reboots — the attack window closes.

### Signing Key Generation and Chain of Trust

The paper actually uses two different attestation key systems, and you've put your finger on something important: it does not use App Attest. App Attest (DCAppAttestService) returns false for isSupported on macOS — that's stated explicitly in Section 1 as one of the motivating constraints. So there's no App Attest chain here at all. Let me trace what actually exists:

The Layer 1 Secure Enclave key (P-256):

Generated on first run via CryptoKit's SecureEnclave.P256.Signing.PrivateKey. The key is created inside the SE, and the application receives only an opaque handle (dataRepresentation). The chain of trust here is implicit and weak on its own: the coordinator receives a public key and a signature, but cannot cryptographically distinguish "this signature came from a real Secure Enclave" from "this signature came from software that generated a P-256 key normally." Both produce identical ECDSA signatures.

This is exactly the limitation the paper acknowledges in Section 7.2: "the coordinator cannot prove the P-256 signing key resides in the Secure Enclave rather than in software, since both produce identical ECDSA signatures."

The Layer 3 ACME/MDA key (P-384):

This is the key with a real cryptographic chain of trust. Generated via the ACME device-attest-01 protocol with HardwareBound = true and Attest = true in the configuration profile. The chain is:

- Device generates a P-384 key inside the Secure Enclave
- Device contacts Apple's attestation servers
- Apple verifies the device using SE hardware attestation capabilities
- Apple issues an X.509 certificate chain:
  - Leaf: device certificate with Apple-assigned OIDs encoding serial number, UDID, OS version, SepOS version, LLB version, SIP status, Secure Boot level
  - Intermediate: Apple Enterprise Attestation Sub CA 1 (P-384)
  - Root: Apple Enterprise Attestation Root CA (P-384, valid until 2047)

The coordinator validates this chain against the embedded Apple root CA. This is what gives "Tier 2 (hardware)" its strength — it's a genuine Apple-signed proof that this is real Apple Silicon with the reported security state.

### The clever bit — binding the two keys together:

Section 9.3 describes an interesting workaround. Apple's MDA-generated keys are stored in a platform-restricted keychain that third-party apps can't access, even with Developer ID signing. So the MDA P-384 key is verifiable but unusable for the actual inference protocol. The paper bridges this gap using the MDA attestation nonce as a binding channel:

- Provider generates SE P-256 key k, sends pk_k to coordinator
- Coordinator computes n = base64(SHA-256(pk_k))
- Coordinator sends MDM DeviceInformation command with DeviceAttestationNonce = n
- Apple generates a fresh MDA cert chain with FreshnessCode = SHA-256(n) baked into the leaf certificate
- Coordinator verifies the chain and confirms FreshnessCode == SHA-256(n)

This cryptographically binds the usable P-256 key to the Apple-attested genuine hardware, without ever having to use the platform-restricted MDA key directly for signing. It's a binding via a third party (Apple) rather than a direct chain.

Summary of the trust chain:

```
Apple Enterprise Attestation Root CA (P-384, hardcoded in coordinator)
    │
    └─► Apple Enterprise Attestation Sub CA 1 (P-384)
            │
            └─► Device Leaf Certificate (P-384)
                  │  - serial, UDID, OS version, SepOS version
                  │  - SIP status, Secure Boot level (Apple-verified)
                  │  - FreshnessCode = SHA-256(SHA-256(pk_SE_P256))  ◄── binding
                  │
                  └─► [via FreshnessCode binding]
                       SE P-256 signing key (used for actual attestations
                       and per-response inference signatures)
```

So the answer to "is there a chain of trust the attestation key binds to": yes, but not via App Attest — via Apple's Enterprise Attestation Root CA through MDA, with a nonce-based cryptographic binding to the actually-used SE signing key. The clever part is that the binding works around macOS not exposing the attested key directly to third-party applications.

One thing the paper is honest about and worth flagging: this whole MDA pathway requires the device to be enrolled with an organization that has Apple attestation authority (Apple Business Manager or equivalent). For arbitrary consumer Mac minis, that's a non-trivial deployment friction listed under Limitations.

### Can you explore other software approaches that maybe don't require a kernel zero-day - what are other ways to access memory on a mach kernel device?

1) Can you explore other software approaches that maybe don't require a kernel zero-day - what are other ways to access memory on a mach kernel device? 
2) How does enrollment in an organization with Apple Attestation authority work? Is a Mac developer account enough?

Excellent questions. Let me dig into both, because the first one in particular is where I think the paper's threat model has more interesting edges than it acknowledges.

1) Other Software Approaches to Access Memory on Mach/XNU
The paper enumerates a clean list of defenses, but Mach/XNU has a richer set of memory access mechanisms than task_for_pid and mach_vm_read. Let me walk through what I'd actually probe if I were trying to find a non-zero-day path.

Mach task ports and the processor_set family. The classical Mach API has processor_set_tasks() which historically returned task ports for all tasks on the system. Apple has progressively locked this down — modern macOS requires task_for_pid-allow entitlement and the calling process to have a stronger code signature than the target. With Hardened Runtime and no get-task-allow on the target, this path is closed. But processor_set_tasks_with_flavor() exists with different flavor types (TASK_FLAVOR_CONTROL, TASK_FLAVOR_READ, TASK_FLAVOR_INSPECT, TASK_FLAVOR_NAME). The read and inspect flavors are subject to the same Hardened Runtime restrictions, but historically there have been bugs where the flavor checks weren't enforced uniformly. Not a current attack, but a probe surface.

Code injection via DYLD_INSERT_LIBRARIES and friends. This is the obvious one — inject a dylib into the inference process and read memory from inside it. Defeated by Hardened Runtime, which strips DYLD_* environment variables on launch unless the binary opts in via the com.apple.security.cs.allow-dyld-environment-variables entitlement. The paper's binary won't have that.

Mach exception ports. Every Mach task has exception ports that receive notifications on faults. task_set_exception_ports() from outside the target requires the same task port access that's already blocked. But there's a subtler variant: host_set_exception_ports() sets host-level exception handlers that fire for any task. This requires host_priv port access, which requires root and specific entitlements on modern macOS. On older macOS this was a real path; today it's gated. Worth checking if any Apple-signed daemon has the entitlement and could be coerced.

The shared memory and IOKit angle. This is the most interesting one for the paper's specific design. The inference engine uses MLX → Metal → Apple Silicon GPU. Metal buffers backed by MTLBuffer with MTLStorageModeShared are mapped into a shared memory region accessible to both CPU and GPU. The paper's Section 6.4 mentions makeBuffer(bytesNoCopy:) from a hypervisor-mapped pool, which is good — but the question is whether any IOKit user client (IOAccelerator, IOGPU, AGXAccelerator) exposes a memory-mapping interface from outside the inference process. If a different process can open an IOKit user client to the GPU and request a mapping of GPU memory, and the GPU memory contains in-flight activations, that's an out-of-band path. Apple has hardened this significantly — the AGX kext checks task identity and codesigning — but it's a non-trivial attack surface that's not covered by PT_DENY_ATTACH or Hardened Runtime, because it doesn't go through the target process's task port at all.

The page-cache / mmap of swap. macOS uses compressed memory and, under pressure, can swap to disk. The paper mentions memory sanitization with write_volatile after each request, but compressed memory in the kernel's compressor pool could in principle hold copies. Reading raw swap requires root and SIP-protected paths — /private/var/vm/ is SIP-protected. So this is mostly blocked, but it depends on whether the inference process pages at all. With 76 GB of model weights pinned in memory, there may be activation pressure that triggers compression of other process memory, evicting it. If the prompt buffer ever lands in the compressor and the compressor's backing store is examined by another mechanism... it's speculative, but the sanitization story is only as good as the assumption that data never leaves the wired region.

mlock and wired memory. The paper doesn't explicitly say it mlocks prompt buffers. If prompts can be paged or compressed, that's a leak path even without explicit memory inspection — the kernel itself moved the data somewhere else. A defense-conscious implementation would mlock all sensitive buffers, but mlock has limits and requires specific entitlements at scale.

DTrace via SIP-allowed providers. DTrace is restricted under SIP — you can't trace SIP-protected processes, and PT_DENY_ATTACH blocks the pid provider. But DTrace has system-wide providers (syscall, sched, vminfo, io) that don't attach to a specific process. These can reveal timing, syscall patterns, and memory pressure events, which is a side-channel rather than a content extraction. Useful for fingerprinting prompt length and structure but not for reading prompt content.

Endpoint Security framework. ES clients (com.apple.developer.endpoint-security.client entitlement) get notifications about process events, file operations, and IPC. They don't get memory contents, but they get file paths, exec arguments, and IPC metadata. If the inference path touches the filesystem at all (model loading, tokenizer files, log files), an ES client running as a different process can observe those reads — including timing. Again, not content extraction, but a richer side channel than the paper acknowledges. ES requires Apple to grant the entitlement, but a malicious provider with an enrolled developer account can get it.

fs_usage, sample, spindump, sysdiagnose. These Apple-signed diagnostic tools have entitlements that let them inspect processes more deeply than third-party tools. sample collects stack traces; spindump collects backtraces from all processes including SIP-protected ones. They generally don't read arbitrary memory, but they do read register state and stack contents at sample points. If a prompt string is on the stack at sample time, spindump output could leak fragments. The paper's defense against this is that the binary has Hardened Runtime without get-task-allow, which should block these tools — but Apple-signed diagnostic tools sometimes have entitlements that override this. Worth verifying empirically against the specific build.

The Rosetta and virtualization path. Not applicable here since the inference is native ARM64, but worth mentioning: if the process were running under Rosetta, the translation layer creates a different memory layout. Not a vector for this paper.

Speculative execution and microarchitectural attacks. PACMAN, Augury, GoFetch (the prefetcher attack on Apple Silicon from 2024) — these are software attacks that don't require a kernel zero-day. GoFetch in particular can extract cryptographic keys from constant-time implementations on M1/M2/M3 by exploiting the data memory-dependent prefetcher. For inference, this is more of a threat to the signing keys if they're used in the same process and within the same security domain than to prompts directly, but attacking the X25519 long-term encryption key via GoFetch-style attacks is a real avenue. The paper's defense surface doesn't address microarchitectural side channels at all. This is a significant gap.

The vmmap and heap tools. These use the same task port mechanisms as lldb, so they're blocked by Hardened Runtime. Confirmed closed.

Kernel debugging via NMI / debug-boot. Holding a specific key combination at boot enables kernel debugging on macOS. With debugging enabled, an attached host can read all kernel and userspace memory via the kernel debug protocol over network or USB. This requires a reboot and the debug= boot-arg, which requires SIP disabled to set on Apple Silicon. So you're back to the reboot-and-detect scenario the paper handles via attestation. But there's a subtlety: if a provider can set boot-args without fully disabling SIP (some boot-args have different protection levels), they might enable kernel debugging while passing SIP checks. Worth a careful audit of the csr-active-config bitmap and which boot-args each bit controls.

The big one the paper does mention: RDMA. I covered this earlier, but worth restating that DMA-capable peripherals are a software-accessible attack vector in the sense that no zero-day is needed — just configuration changes. The paper handles this with the hypervisor.

My honest assessment: the paper's enumeration is solid for the common memory-access APIs but light on (a) GPU memory access via IOKit, (b) microarchitectural side channels like GoFetch, (c) Apple-signed diagnostic tool entitlements that may have memory-adjacent capabilities, and (d) the wired-vs-pageable status of sensitive buffers. None of these are kernel zero-days. They're underexplored regions of the macOS security model.

2) How Apple Attestation Authority Enrollment Actually Works
Short answer: a regular Apple Developer account is not enough. Here's the full picture.

The required infrastructure for ACME device-attest-01 and Managed Device Attestation is Apple Business Manager (ABM) or Apple School Manager (ASM). These are organizational programs separate from the Apple Developer Program, and they're what gives an organization "attestation authority" in Apple's ecosystem.

To enroll a Mac in MDA, you need:

- An Apple Business Manager account (free, but requires a D-U-N-S number and verification that you're a legitimate business entity). Apple manually reviews these — it's not instant, and they reject sole proprietors and some small operations.
- An MDM server that's been authorized in ABM. The paper uses MicroMDM. Your MDM server's identity certificate is uploaded to ABM, which establishes the trust relationship.
- Devices added to ABM, which happens via one of two pathways:
  - Automated Device Enrollment (ADE): the device was purchased through Apple Business / a participating reseller and Apple's records show your organization owns it. The device auto-enrolls in your MDM on first boot.
  - Manual enrollment via Apple Configurator: you physically connect a Mac to another Mac running Apple Configurator 2, wipe it, and add it to ABM. The user gets a 30-day "provisional period" during which they can release the device, but after that it's locked in.

A configuration profile (the .mobileconfig the paper describes) signed by your MDM that includes the ACME payload requesting Attest = true. This is what triggers Apple's attestation servers to issue the MDA certificate chain.

What a regular Apple Developer account gets you: code signing certificates, provisioning profiles, App Store distribution, notarization, push notification capabilities, App Attest for iOS apps. It does not get you the ability to request MDA certificates for Macs.

Why this matters for the paper's deployment story: the paper acknowledges this in Section 16 as a limitation, and it's a serious one. The system as described requires every provider Mac to be enrolled in the operator's ABM organization. This means:

- The provider has to either purchase the Mac through a channel that lets it be added to the operator's ABM, or hand-deliver it (or use Apple Configurator remotely with cooperation) to be enrolled
- The provider technically becomes "managed" by the operator's MDM, even though the paper carefully restricts AccessRights to bits 0, 4, and 10 (inspect, query info, query security only)
- The provider can unenroll at any time via System Settings, but this also revokes their ability to attest
- The trust relationship inversion this creates: in a normal MDM deployment, the organization trusts the device and manages it. Here, the operator (coordinator) needs cryptographic proof about the provider's hardware, and ABM enrollment is the only way Apple lets you get that proof. It's an awkward fit — ABM was designed for IT departments managing employee Macs, not for a decentralized network of independent contributors.

Practical paths forward that the paper doesn't fully spell out:

- The DGInf operator runs a single ABM organization, and every provider enrolls their Mac into it via Apple Configurator. This works but creates friction (provider must run Apple Configurator workflow) and a centralized dependency.
- Use Account-Driven Device Enrollment (introduced in macOS Sonoma), which lets users enroll their personal Macs via a Managed Apple ID without going through ABM purchase records. This is closer to a self-serve flow but still requires the provider to authenticate to the operator's identity provider and accept supervision.
- Wait for Apple to expand attestation availability. There's been speculation that Apple might extend something App Attest-like to macOS, but as of the paper's writing (and now), it hasn't happened.
- An alternative the paper doesn't discuss: you could downgrade to "Tier 1 (self_signed)" without MDA and rely solely on the SE signature plus MDM SecurityInfo (which doesn't require ABM — any MDM enrollment works). This loses the Apple-signed hardware provenance proof but keeps the OS-level security state verification. The paper does define this tier but treats hardware as the production minimum.

Bottom line: a developer account gets you nowhere on this. You need ABM, which means you need a verified business entity with a D-U-N-S number, an MDM server, and a way to get devices enrolled in your organization. For a research deployment with a handful of Mac minis you control, this is achievable in a week or two. For a public decentralized network where anyone can plug in their personal Mac mini, it's a meaningful onboarding obstacle, and the paper's "single shell command" installation story (Section 13) papers over a non-trivial prerequisite.

