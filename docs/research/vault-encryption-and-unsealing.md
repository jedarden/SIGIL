## Part 1: Key Derivation Functions (KDF) -- Cost to Crack

### 1.1 Argon2id

Argon2id is the current gold standard for password hashing and key derivation, winning the Password Hashing Competition (PHC) in 2015 and standardized in RFC 9106. It is a hybrid of Argon2i (data-independent memory access, side-channel resistant) and Argon2d (data-dependent access, GPU/ASIC resistant). Argon2id uses Argon2i for the first half of the first pass over memory and Argon2d for the rest.

**Parameters:**

| Parameter | Description | Typical Range |
|-----------|-------------|---------------|
| `m` (memory) | Memory cost in KiB | 64 MiB - 2 GiB |
| `t` (time) | Number of iterations/passes | 1 - 10 |
| `p` (parallelism) | Number of parallel lanes | 1 - 16 |

**RFC 9106 Recommendations (Section 7.3):**
- Non-interactive: `t=1`, use maximum available memory
- Baseline: `m=64 MiB`, `t=1`
- Higher security: `m=128 MiB`, `t=3`, `p=4`

**OWASP (2025) Recommendations:**
- Minimum: `m=46 MiB` (47,104 KiB), `t=1`, `p=1` (~150-200ms on typical server CPU)
- Recommended: `m=128 MiB`, `t=3`, `p=4` (~300-500ms)

**Brute Force Resistance Mechanics:**

The core defense is that each hash evaluation requires allocating and filling the full memory region. A GPU with 24 GiB VRAM attacking Argon2id with `m=1 GiB` can compute at most 24 hashes in parallel (24 GiB / 1 GiB). Compare this to SHA-256, where the same GPU can compute billions of hashes in parallel.

**Measured GPU Hash Rates (Argon2id, default hashcat parameters m=64 MiB, t=3, p=1):**

| GPU | Hashes/sec |
|-----|-----------|
| RTX 5090 | ~2,400 (estimated) |
| RTX 4090 | 1,900 |
| RTX 4080 | 1,480 |
| RTX 4070 Ti | 1,110 |
| RTX 3090 | 850 |
| RTX 3080 | 690 |
| AMD EPYC 9654 (CPU) | 210 |
| Intel Core i9-14900K (CPU) | 110 |

Source: [GPU Password Cracking Benchmarks 2025](https://www.onlinehashcrack.com/guides/password-recovery/gpu-password-cracking-benchmarks-2025-rtx-vs-cpus.php)

These rates are for the **hashcat default** Argon2id parameters (`m=65536 KiB = 64 MiB, t=3, p=1`). Increasing memory cost to 1 GiB dramatically reduces throughput because each GPU can only compute `floor(VRAM / m)` parallel instances.

**Scaling with Memory Cost:**

For a GPU with 24 GiB VRAM:

| Memory (`m`) | Max parallel instances (24 GiB VRAM) | Estimated H/s per RTX 4090 |
|-------------|--------------------------------------|---------------------------|
| 64 MiB | 384 | 1,900 |
| 256 MiB | 96 | ~475 |
| 512 MiB | 48 | ~240 |
| 1 GiB | 24 | ~120 |
| 2 GiB | 12 | ~60 |

The relationship is roughly linear: doubling memory halves throughput because the bottleneck becomes VRAM capacity.

For the NVIDIA A100 (40 GiB VRAM), throughput at `m=1 GiB` would be approximately `floor(40/1) * (single_hash_rate)`. The A100 has similar per-hash compute to the RTX 4090 but more VRAM, so approximately 40 * 5 = ~200 H/s at `m=1 GiB, t=3`.

**LUKS2 Benchmark (Argon2id, m=1 GiB, default parameters):**

ElcomSoft found that LUKS2 with Argon2 as KDF reduces GPU-accelerated attacks to **CPU-only speeds**: approximately 2 passwords/second on an Intel Core i7-9700K. GPU acceleration becomes **impossible** with Argon2 at high memory settings because the memory requirements exceed what can be efficiently parallelized on GPU.

Source: [ElcomSoft LUKS2 Probing](https://blog.elcomsoft.com/2022/08/probing-linux-disk-encryption-luks2-argon-2-and-gpu-acceleration/)


### 1.2 scrypt

scrypt was designed by Colin Percival in 2009, predating Argon2. It is used by age encryption, Litecoin, and many other systems.

**Parameters:**

| Parameter | Description | Formula for Memory |
|-----------|-------------|-------------------|
| `N` | CPU/memory cost factor (must be power of 2) | Memory = 128 * N * r bytes |
| `r` | Block size multiplier (typically 8) | Affects memory bandwidth |
| `p` | Parallelization factor (typically 1) | Independent instances |

**Recommended Parameters (Filippo Valsorda, 2017):**
- Interactive logins: `N=2^15` (32,768), `r=8`, `p=1` = 4 MiB, ~86ms
- File encryption: `N=2^20` (1,048,576), `r=8`, `p=1` = 128 MiB, ~3.8s

Source: [The scrypt parameters](https://words.filippo.io/the-scrypt-parameters/)

**age encryption defaults:**
- Encryption: `logN=18` (N=262,144), `r=8`, `p=1` = 32 MiB, ~1s
- Max decryption: `logN=22` (N=4,194,304), `r=8`, `p=1` = 512 MiB, ~15s

Source: [age scrypt.go](https://github.com/FiloSottile/age/blob/main/scrypt.go)

**Hashcat Benchmarks (scrypt, default N=16384, r=8, p=1 = 2 MiB):**

| GPU | Hashes/sec |
|-----|-----------|
| H100 PCIe | 8,456 |
| A100 PCIe (4 GPUs) | 5,428 (combined) |

Source: [Hashcat H100 benchmark](https://gist.github.com/Chick3nman/e1417339accfbb0b040bcd0a0a9c6d54), [Hashcat A100 benchmark](https://gist.github.com/Chick3nman/d65bcd5c137626c0fcb05078bba9ca89)

**scrypt vs Argon2id:**

| Property | scrypt | Argon2id |
|----------|--------|----------|
| Memory hardness | Yes (N * r * 128 bytes) | Yes (configurable in KiB) |
| Time hardness | Yes (via N) | Yes (via t iterations) |
| GPU resistance | Good | Better (tunable independently) |
| ASIC resistance | Moderate (Litecoin ASICs exist) | Better (PHC winner, no known ASICs) |
| Side-channel resistance | No (data-dependent access) | Yes (hybrid in Argon2id) |
| Parameter flexibility | N/r/p coupled | m/t/p independent |
| Provable security | Heuristic | Heuristic (but PHC-vetted) |

The critical weakness of scrypt is that **Litecoin mining ASICs exist** that can compute scrypt hashes efficiently. This proves that dedicated hardware can be built for scrypt. No equivalent ASICs exist for Argon2id.


### 1.3 bcrypt

bcrypt dates from 1999 (Provos & Mazieres). It uses a **fixed 4 KiB memory footprint** (the Blowfish state), making it the weakest of the three for GPU/ASIC resistance.

**Parameter:**
- `cost` (work factor): Number of iterations = `2^cost`. Typical range: 10-14.

**Hashcat Benchmarks (bcrypt, cost=5 i.e. 32 iterations):**

| GPU | Hashes/sec |
|-----|-----------|
| RTX 5090 | ~22,000 |
| RTX 4090 | ~14,000 |
| A100 SXM4 | 139,900 |
| A100 PCIe (4 GPUs) | 553,400 |
| H100 PCIe | 251,500 |

Source: Various hashcat benchmarks cited above.

**Why bcrypt is Weaker for This Use Case:**

1. **No memory hardness**: The fixed 4 KiB Blowfish state fits entirely in GPU registers/L1 cache. GPUs can run thousands of parallel bcrypt evaluations.
2. **GPU advantage**: At cost=12 (typical production), a single RTX 4090 can compute ~184 H/s. This is fast enough to crack weak passwords.
3. **FPGA/ASIC attacks**: The small, fixed memory makes bcrypt an ideal FPGA target. Custom bcrypt ASICs would be straightforward to build.
4. **No independent memory tuning**: You cannot increase memory usage without switching algorithms entirely.

**Comparison at Equivalent Wall-Clock Time (~1 second):**

| Algorithm | Parameters | Memory | GPU H/s (RTX 4090) | GPU Advantage Over CPU |
|-----------|-----------|--------|--------------------|-----------------------|
| bcrypt | cost=13 | 4 KiB | ~90 | ~8-16x |
| scrypt | N=2^20, r=8 | 128 MiB | ~10 | ~2-3x |
| Argon2id | m=256 MiB, t=3 | 256 MiB | ~30 | ~1.5x |
| Argon2id | m=1 GiB, t=3 | 1 GiB | ~2 | ~1x (CPU-limited) |


### 1.4 Balloon Hashing

Balloon hashing was proposed by Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter in 2016. It is notable for being the **first practical password hashing function with provable memory-hardness** in the random oracle model.

**Key Properties:**
- Provable memory-hardness (C=8) vs. Argon2i (C=192) and scrypt (C=24), where C is the constant in the space-time tradeoff bound
- Password-independent memory access pattern (like Argon2i, unlike scrypt)
- Simple construction based on standard hash functions
- Two parameters: `s_cost` (memory buffer size) and `t_cost` (mixing rounds)

**Comparison with Argon2id:**

| Property | Balloon | Argon2id |
|----------|---------|----------|
| Provable security | Yes (strongest proof) | Heuristic |
| Practical performance | Competitive | Slightly better |
| GPU resistance | Good | Better (hybrid access) |
| Standardization | NIST considering | RFC 9106 |
| Implementation maturity | Limited | Widespread |
| Adoption | Low | High (OWASP recommended) |

**Status:** NIST has been considering Balloon hashing in the revision of SP 800-132. However, the algorithm details are not yet finalized with official test vectors, which means OWASP and the broader security community still recommend Argon2id for production use.

Source: [Balloon Hashing (Boneh et al., 2016)](https://eprint.iacr.org/2016/027.pdf)


### 1.5 Real-World Cost Calculations: $1 Billion Brute Force Target

**AWS GPU Infrastructure Costs:**

| Instance | GPUs | GPU Memory | On-Demand $/hr | Spot $/hr |
|----------|------|-----------|----------------|-----------|
| p4d.24xlarge | 8x A100 40 GiB | 320 GiB | $32.77 | ~$10.40 |
| p4de.24xlarge | 8x A100 80 GiB | 640 GiB | $40.97 | ~$16.00 |
| p5.48xlarge | 8x H100 80 GiB | 640 GiB | $98.32 | ~$35.00 |

Source: [Vantage p4d.24xlarge pricing](https://instances.vantage.sh/aws/ec2/p4d.24xlarge)

Note: The $32.77/hr figure represents the on-demand price in some regions; other regions show $21.96/hr. We use the lower figure for conservative (attacker-favorable) calculations.

**Cost-to-Crack Calculation Framework:**

The cost to brute-force a vault is:

```
Cost = (2^entropy / hashes_per_second) * cost_per_second
```

Where:
- `2^entropy` = size of the password search space
- `hashes_per_second` = attacker's throughput
- `cost_per_second` = hardware rental cost

For the **expected** (average) cost, divide by 2 (attacker finds the password after searching half the space on average).

**Scenario: Argon2id with m=1 GiB, t=3, p=4**

At `m=1 GiB`, an A100 with 40 GiB VRAM can compute at most 40 parallel hashes. Accounting for computational overhead with `t=3` iterations, realistic throughput per A100 is approximately 20 H/s. A p4d.24xlarge with 8x A100s achieves approximately **160 H/s**.

At $21.96/hr (spot: $10.40/hr), cost per hash:
- On-demand: $21.96 / 3600 / 160 = $0.0000381 per hash
- Spot: $10.40 / 3600 / 160 = $0.0000181 per hash

**Password Entropy vs. Cost to Crack (Argon2id m=1 GiB, t=3, on p4d.24xlarge spot pricing):**

| Entropy (bits) | Search Space | Time (8x A100) | Cost (spot) |
|----------------|-------------|-----------------|-------------|
| 40 | 1.1 x 10^12 | 80 days | $20,000 |
| 50 | 1.1 x 10^15 | 224 years | $20 million |
| 60 | 1.2 x 10^18 | 229,000 years | $21 billion |
| 70 | 1.2 x 10^21 | 234 million years | $21 trillion |
| 80 | 1.2 x 10^24 | 240 billion years | $21 quadrillion |

**To reach the $1 billion target on spot pricing:**

```
$1,000,000,000 = (2^E / 2) * $0.0000181
2^E = 2 * $1,000,000,000 / $0.0000181
2^E = 1.1 x 10^14
E = log2(1.1 x 10^14) = ~46.6 bits
```

With Argon2id `m=1 GiB, t=3` on a p4d.24xlarge at spot pricing: **~47 bits of entropy** makes brute force cost $1 billion on average.

But this is a single instance. An attacker with unlimited budget can parallelize across many instances. However, the cost scales linearly -- using 1,000 instances doesn't reduce cost, only time. The **total cost remains the same** regardless of parallelization.

**Conservative Calculation (accounting for future hardware improvements):**

Assume a 10x improvement in GPU efficiency over the next decade (generous -- memory bandwidth is the bottleneck and improves slowly):

```
Required entropy = 47 + log2(10) = 47 + 3.3 = ~51 bits
```

**For the $1 billion target with safety margin, SIGIL should require:**

| KDF Parameters | Minimum Password Entropy | Equivalent Passphrase |
|---------------|-------------------------|----------------------|
| Argon2id m=1 GiB, t=3 | 55 bits | 5 diceware words |
| Argon2id m=1 GiB, t=3 | 65 bits (10-year margin) | 6 diceware words |
| Argon2id m=2 GiB, t=4 | 52 bits | 5 diceware words |
| Argon2id m=2 GiB, t=4 | 62 bits (10-year margin) | 5-6 diceware words |


### 1.6 Password Entropy Requirements

**Entropy Sources:**

| Method | Entropy per Unit | Example |
|--------|-----------------|---------|
| Diceware (EFF, 7776 words) | 12.9 bits/word | "correct horse battery staple" = 51.7 bits |
| Random alphanumeric (a-zA-Z0-9) | 5.95 bits/char | 10 chars = 59.5 bits |
| Random printable ASCII | 6.57 bits/char | 10 chars = 65.7 bits |
| BIP39 mnemonic (2048 words) | 11 bits/word | 6 words = 66 bits |
| Random hex | 4 bits/char | 16 chars = 64 bits |

Source: [EFF Diceware Wordlists](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases)

**User-Chosen Passwords:**

Human-chosen passwords typically have 10-30 bits of entropy, depending on length and complexity. Even "strong" user-chosen passwords rarely exceed 40 bits because humans are terrible at randomness.

**SIGIL Recommendation:**

For $1B brute-force resistance with Argon2id (m=1 GiB, t=3):
- **Minimum**: 6 diceware words (77.5 bits) -- provides $10^15 in cracking cost
- **Recommended**: 7 diceware words (90.4 bits) -- provides $10^19 in cracking cost
- **Alternative**: 12 random alphanumeric characters (71.4 bits) -- provides $10^13 in cracking cost

With the KDF doing the heavy lifting, even a 5-word diceware passphrase (64.6 bits) exceeds the $1B target by orders of magnitude. But given that the vault is publicly committed to git, a safety margin of at least 2-3 orders of magnitude is prudent. **6 diceware words (77.5 bits) is the recommended minimum.**

**Critical Insight:** The combination of a strong KDF and sufficient password entropy is multiplicative. Argon2id with m=1 GiB adds roughly 47 bits of "effective entropy" (i.e., it costs 2^47 times more to crack than a plain SHA-256 hash). So the total effective security is:

```
effective_bits = password_entropy + log2(KDF_cost_factor)
```

For 6 diceware words + Argon2id m=1 GiB, t=3:
```
effective_bits = 77.5 + 47 = ~124.5 bits
```

This is solidly in the "nation-state-resistant" range.

---

## Part 2: Cryptocurrency Cryptography Patterns

### 2.1 BIP39 Mnemonic Seeds

**How It Works:**

1. Generate random entropy: 128 bits (12 words) or 256 bits (24 words)
2. Compute checksum: SHA-256 of entropy, take first `entropy_bits / 32` bits
3. Append checksum to entropy
4. Split into 11-bit groups (each maps to one of 2048 words in the BIP39 wordlist)
5. Derive binary seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + optional_passphrase, iterations=2048, dkLen=64)

**Entropy Provided:**

| Words | Entropy Bits | Checksum Bits | Total Bits |
|-------|-------------|---------------|------------|
| 12 | 128 | 4 | 132 |
| 15 | 160 | 5 | 165 |
| 18 | 192 | 6 | 198 |
| 21 | 224 | 7 | 231 |
| 24 | 256 | 8 | 264 |

Source: [BIP-0039 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

**Relevance to SIGIL:**

SIGIL could use a BIP39-like mnemonic for vault master key backup:
- Generate 256 bits of entropy from CSPRNG
- Encode as 24-word mnemonic for human-readable backup
- User writes down the 24 words on paper as emergency recovery
- Mnemonic is processed through Argon2id (not PBKDF2 with only 2048 iterations as in BIP39) to derive the actual vault encryption key

**Key Differences from BIP39 for SIGIL:**
- BIP39 uses PBKDF2 with only 2048 iterations (weak by modern standards) because wallet recovery needs to be fast
- SIGIL should use Argon2id with strong parameters since vault opening is infrequent
- The mnemonic provides the entropy; the KDF provides the brute-force resistance
- A 24-word mnemonic with 256 bits of entropy + Argon2id makes brute force permanently infeasible


### 2.2 Shamir's Secret Sharing (SSS) and SLIP-39

**How SSS Works:**

Shamir's Secret Sharing (Adi Shamir, 1979) splits a secret into `n` shares such that any `k` (threshold) of them can reconstruct the secret, but `k-1` shares reveal absolutely nothing about the secret. It uses polynomial interpolation over a finite field:

1. Represent the secret `S` as the constant term of a random polynomial of degree `k-1`
2. Choose `k-1` random coefficients: `f(x) = S + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1) mod p`
3. Generate shares as `(i, f(i))` for `i = 1, 2, ..., n`
4. Reconstruction uses Lagrange interpolation on any `k` shares

**Information-theoretic security**: With fewer than `k` shares, the secret is perfectly hidden -- not just computationally hard, but information-theoretically impossible to determine.

**SLIP-39 Standard:**

SLIP-39 (SatoshiLabs, implemented in Trezor Model T, Safe 3, Safe 5) standardizes SSS for cryptocurrency recovery:
- Each share is encoded as 20 or 33 words from a 1024-word wordlist (10 bits/word)
- Supports **two-level sharing**: first split into groups, then each group has its own threshold
- Example: 2-of-3 groups where Group A is "2-of-3 family members", Group B is "2-of-3 lawyers", Group C is "1-of-1 bank safe deposit box"
- The master secret is processed through PBKDF2-HMAC-SHA256 with 20,000 iterations plus an optional passphrase

Source: [SLIP-0039 Specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)

**SIGIL Application:**

SIGIL could implement M-of-N key splitting for vault recovery:
- Split the vault master key into, e.g., 3-of-5 shares
- Store shares on separate devices, locations, or with trusted parties
- Any 3 shares reconstruct the master key
- Losing 2 shares does not compromise the vault

**Criticisms (from Bitcoin community):**

The "Shamir Secret Snakeoil" article on the Bitcoin Wiki raises valid concerns:
- Reconstruction requires all `k` shares to be brought together in one place (single point of failure during reconstruction)
- The trusted dealer problem: who generates the original shares? They see the full secret
- No verifiable secret sharing: a malicious dealer can give invalid shares that fail during reconstruction

Source: [Shamir Secret Snakeoil - Bitcoin Wiki](https://en.bitcoin.it/wiki/Shamir_Secret_Snakeoil)


### 2.3 Multi-Signature (Multisig)

**How It Works:**

Multisig requires `M` of `N` independent keys to authorize an operation:

- **Bitcoin**: Implemented at the script level using `OP_CHECKMULTISIG`. A 2-of-3 multisig address requires any 2 of 3 specified public keys to sign a transaction. The script enforces this on-chain.

- **Ethereum**: Implemented via smart contracts (e.g., Gnosis Safe). The contract maintains a list of authorized signers and a threshold. Each operation requires enough valid signatures before execution.

Source: [Ledger Academy: Multisig Wallets](https://www.ledger.com/academy/what-is-a-multisig-wallet)

**SIGIL Application:**

For vault unsealing, SIGIL could require multiple independent authentication factors -- conceptually similar to multisig:

```
Vault Key = Unseal(passphrase, device_key, yubikey_hmac)
        requires all 3 (3-of-3)
   -- OR --
Vault Key = Unseal(any 2 of: passphrase, device_key, yubikey_hmac, recovery_code)
        requires 2-of-4
```

This is not true multisig (which involves digital signatures on transactions) but rather **multi-factor key derivation** -- combining multiple secrets into a single encryption key. The MFKDF construction (Section 4.6) is more appropriate than actual multisig for this use case.


### 2.4 Hardware Wallet Security Models

**Ledger (Secure Element):**
- Uses a certified secure element (ST33J2M0 or later) -- the same chip technology as in credit cards and passports
- Private keys **never leave** the secure element
- All cryptographic operations happen inside the chip
- Supports FIDO U2F (not full FIDO2) as a separate application
- PIN-protected with wipe after 3 failed attempts

**Trezor (Open-Source, No Secure Element in Classic Models):**
- Trezor Model One and Model T use general-purpose MCUs (no secure element)
- Trezor Safe 3/5/7 added a secure element (Optiga Trust M)
- Supports full FIDO2/WebAuthn including passkeys and hmac-secret
- Unlimited FIDO2 credentials (stored on device)
- PIN-protected with exponential backoff

**YubiKey (FIDO2 + More):**
- Hardware-based FIDO2/WebAuthn authenticator
- Supports `hmac-secret` extension (CTAP2) -- critical for offline vault encryption
- Up to 100 FIDO2 credentials (firmware 5.7+)
- Also supports PIV, OpenPGP, OTP, and Challenge-Response (HMAC-SHA1)
- Tamper-resistant with no extractable secrets

**SIGIL Application:**

The most practical hardware key integration for SIGIL is the **FIDO2 hmac-secret extension** via YubiKey (or any FIDO2 authenticator supporting this extension). This allows deriving a deterministic cryptographic secret from the hardware key without any server involvement.


### 2.5 Hierarchical Deterministic (HD) Wallets / BIP32

**How It Works:**

BIP32 derives an entire tree of cryptographic keys from a single master seed:

1. **Master Key Generation**: `HMAC-SHA512(Key="Bitcoin seed", Data=seed)` produces 64 bytes. Left 32 bytes = master private key, right 32 bytes = master chain code.

2. **Child Key Derivation** (two types):
   - **Hardened**: `HMAC-SHA512(chain_code, 0x00 || private_key || index)` -- child key cannot be derived without parent private key
   - **Normal**: `HMAC-SHA512(chain_code, public_key || index)` -- child public keys derivable from parent public key

3. **Path notation**: `m/44'/0'/0'/0/0` where `'` denotes hardened derivation

Source: [BIP-0032 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

**SIGIL Application:**

SIGIL could use an HD-like derivation scheme for per-secret keys:

```
master_key = Argon2id(passphrase, salt, params)
secret_key[i] = HKDF-SHA256(master_key, info="sigil/v1/secret/" + secret_path)
```

Benefits:
- Each secret encrypted with a unique key derived from the master
- Compromise of one derived key does not expose the master or other secrets
- Deterministic: the same master key always produces the same derived keys
- No need to store derived keys -- they are recomputed on-the-fly

HKDF (RFC 5869) is simpler and more appropriate than BIP32 for this use case since SIGIL does not need the public-key derivation or chain code properties of BIP32.


### 2.6 Threshold Signatures (TSS) and FROST

**FROST (Flexible Round-Optimized Schnorr Threshold Signatures):**

FROST (RFC 9591) is a two-round Schnorr threshold signature protocol where `t` of `n` participants can jointly produce a valid signature without any single party ever seeing the full private key.

**Key Differences from Shamir's Secret Sharing:**

| Property | Shamir's SS | FROST/TSS |
|----------|------------|-----------|
| Key exists in one place | Yes (during setup by dealer) | Never (distributed key generation) |
| Reconstruction required | Yes (secret reassembled) | No (signature produced without reconstruction) |
| Dealer trust | Required | Not required (DKG protocol) |
| Output | The secret itself | A signature (secret never reconstructed) |
| Online operation | No (offline reconstruction) | Yes (interactive signing) |

Source: [FROST RFC 9591](https://datatracker.ietf.org/doc/rfc9591/), [Blockchain Commons FROST](https://developer.blockchaincommons.com/frost/)

**SIGIL Relevance:**

TSS/FROST is less relevant to SIGIL than SSS because:
- SIGIL needs to **reconstruct the decryption key** to decrypt the vault (SSS use case)
- FROST is designed for **producing signatures** without reconstructing the key
- For vault encryption, the key must eventually exist in memory to decrypt, so FROST's "key never assembled" property doesn't help

SSS is the correct primitive for SIGIL's vault recovery use case.


### 2.7 Zero-Knowledge Proofs

**What They Are:**

A zero-knowledge proof allows one party (the prover) to convince another party (the verifier) that a statement is true without revealing any information beyond the truth of the statement itself.

**Password Manager "Zero-Knowledge":**

The term "zero-knowledge" in password managers (1Password, Bitwarden, LastPass, NordPass, Dashlane) is a **marketing term** that refers to the architectural property that the server never sees the user's master password or unencrypted vault data. This is not the same as a zero-knowledge proof in the cryptographic sense.

**SIGIL Application:**

True ZK proofs have limited applicability to SIGIL's core vault encryption use case:

1. **Proving secret validity**: SIGIL could use a ZKP to prove to an agent that "I possess a valid API key for service X" without revealing the key. However, this is unnecessary because SIGIL already handles this through the `{{secret:path}}` placeholder mechanism.

2. **Audit proofs**: SIGIL could prove that a secret was used at a specific time without revealing the secret value. This could be useful for compliance but adds significant complexity.

3. **Vault integrity**: ZKPs could prove that the vault has not been tampered with without revealing its contents. However, authenticated encryption (AES-GCM, ChaCha20-Poly1305) already provides tamper detection.

**Verdict**: ZKPs add complexity without solving a problem SIGIL does not already handle through simpler mechanisms. Not recommended for the initial design.


### 2.8 Post-Quantum Cryptography

**Quantum Threat Model:**

| Cryptographic Primitive | Quantum Impact | Effective Security |
|------------------------|---------------|-------------------|
| AES-256 | Grover's algorithm halves key space | 128-bit post-quantum (adequate) |
| ChaCha20 (256-bit key) | Grover's algorithm halves key space | 128-bit post-quantum (adequate) |
| SHA-256 | Grover's provides sqrt speedup | 128-bit post-quantum (adequate) |
| Argon2id | Memory-hardness limits Grover's parallelism | Largely unaffected |
| RSA, ECDH, ECDSA | Shor's algorithm breaks completely | 0-bit post-quantum (broken) |
| ML-KEM-768 (Kyber) | Designed to resist quantum | 128-bit post-quantum |

Source: [Post-Quantum Password Hashes: Argon2 Fate](https://www.onlinehashcrack.com/guides/post-quantum-crypto/post-quantum-password-hashes-argon2-fate.php), [Practical Cryptography for Developers](https://cryptobook.nakov.com/quantum-safe-cryptography)

**Key Insight for SIGIL:**

SIGIL's vault encryption (Argon2id KDF + ChaCha20-Poly1305 or AES-256-GCM) is **already substantially quantum-resistant** because:

1. The KDF (Argon2id) is a symmetric primitive. Grover's algorithm theoretically halves the effective entropy, but memory-hardness makes quantum parallelism impractical.
2. The cipher (ChaCha20/AES-256) has 256-bit keys, providing 128-bit post-quantum security.
3. No asymmetric cryptography is used in the basic vault encryption path.

The quantum vulnerability would be in any **key exchange** or **public-key encryption** layers. If SIGIL uses age's X25519 recipients for multi-device sync, those would need replacement with ML-KEM-768. The age tool has ongoing discussions about native ML-KEM support.

Source: [age Post-quantum crypto discussion](https://github.com/FiloSottile/age/discussions/231), [Filippo Valsorda on ML-KEM-768](https://words.filippo.io/mlkem768/)

**Recommendation:**
- Vault encryption (KDF + symmetric cipher): already quantum-safe, no changes needed
- If asymmetric encryption is needed later (multi-device, key sharing): use hybrid ML-KEM-768 + X25519

---

## Part 3: Password Manager Security Models

### 3.1 KeePass / KeePassXC (KDBX4 Format)

**Encryption:**
- AES-256-CBC or ChaCha20 (256-bit key), per RFC 8439
- HMAC-SHA256 authentication in 1 MiB blocks
- Randomly generated IV per save operation

**Key Derivation:**
- **AES-KDF**: Iterates AES encryption of the key (legacy, KeePass 1.x/2.x)
- **Argon2d** or **Argon2id**: Memory-hard KDF (KeePass 2.x, KDBX4)
  - Recommended: `t >= 2`, `m = min(RAM/2, 1 GiB)`, `p >= logical_processor_count`

**Composite Key Construction:**

KeePass combines multiple key sources into a single 256-bit key:

```
composite_key = SHA-256(SHA-256(password) || key_file_contents || windows_user_key || plugin_keys)
derived_key = Argon2id(composite_key, random_salt, params)
encryption_key = SHA-256(main_seed || derived_key)
hmac_key = SHA-512(main_seed || derived_key || 0x01)
```

Where `main_seed` is a 32-byte random value stored in the database header.

**Key File:**
- 32-byte random file that acts as a second factor
- Stored on a separate device (USB drive, etc.)
- Not password-protected itself -- security through physical possession

**Challenge-Response (YubiKey):**
- KeePassXC supports YubiKey via HMAC-SHA1 Challenge-Response (Slot 2)
- The challenge is derived from the `main_seed` header field
- YubiKey's 20-byte HMAC-SHA1 response is incorporated into the composite key
- KeePassXC is working on FIDO2 hmac-secret support (GitHub discussion #9506)

Source: [KeePass Security](https://keepass.info/help/base/security.html), [KDBX4 Format](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/), [KeePassXC FIDO2 discussion](https://github.com/keepassxreboot/keepassxc/discussions/9506)

**Relevance to SIGIL:**

KeePass's composite key model is directly applicable. SIGIL should:
- Support password + key file + hardware key as independent factors
- Hash each factor independently, concatenate, then hash again
- Feed the composite key into Argon2id
- Store a random salt and main seed in the vault header


### 3.2 1Password (Two-Secret Key Derivation)

**Architecture:**

1Password uses Two-Secret Key Derivation (2SKD) combining:
- **Account Password**: User-chosen master password
- **Secret Key**: 128-bit (26-character, e.g., `A3-ASWBYB-798JRY-LJUT4-23TES-Q24TX-J5CC2`) generated on account creation, stored on device, never sent to 1Password servers

**Key Derivation Process:**

```
input = account_password || secret_key
AUK = HKDF(PBKDF2(input, salt_auk, 650000), info="AUK")
SRP-x = HKDF(PBKDF2(input, salt_srp, 650000), info="SRP")
```

- AUK (Account Unlock Key): Decrypts the user's vault key hierarchy
- SRP-x: Used for authentication via Secure Remote Password protocol

**Why 2SKD is Brilliant:**

1. **Server-side brute force impossible**: Even if 1Password's servers are fully compromised, attackers cannot brute-force the vault because they lack the Secret Key (128 bits of entropy that was never sent to the server)
2. **Weak password tolerance**: A user with a weak 30-bit password still has 30 + 128 = 158 bits of effective entropy
3. **Device binding**: The Secret Key is stored only on authorized devices

**SRP (Secure Remote Password) Protocol:**

SRP allows the client to authenticate to the server by proving knowledge of the password without ever transmitting the password or its hash. The server stores only a "verifier" derived from the password, and an attacker who compromises the server cannot use the verifier to impersonate the user.

Source: [1Password Security Design](https://support.1password.com/1password-security/), [1Password Authentication](https://support.1password.com/authentication-encryption/), [1Password Deep Keys](https://agilebits.github.io/security-design/deepKeys.html)

**Relevance to SIGIL:**

1Password's 2SKD model is highly relevant for SIGIL's git-committed vault:

- **Passphrase** (user-remembered, moderate entropy) + **Device Key** (128+ bits, stored on device) = brute force infeasible even with weak passphrase
- The vault file in git is useless without the device key, which never appears in the repository
- This is the strongest practical defense for a publicly-committed encrypted vault


### 3.3 Bitwarden

**Key Derivation:**

Two options (user-selectable):

1. **PBKDF2-SHA256**: 600,000 iterations (default for legacy accounts)
2. **Argon2id**: `m=64 MiB, t=3, p=4` (recommended, OWASP-aligned)
   - Max configurable: `t=10, p=16`

**Encryption Flow:**

```
master_key = Argon2id(password, email_as_salt, m=64MB, t=3, p=4)
stretched_key = HKDF-Expand(master_key, info="enc", len=32) || HKDF-Expand(master_key, info="mac", len=32)
```

Vault data encrypted with AES-256-CBC, authenticated with HMAC-SHA256. The master key never leaves the client device.

Source: [Bitwarden KDF Algorithms](https://bitwarden.com/help/kdf-algorithms/), [Bitwarden Security White Paper](https://bitwarden.com/help/bitwarden-security-white-paper/)

**Weakness Compared to 1Password:**

Bitwarden uses only the master password for key derivation (no equivalent of 1Password's Secret Key). If Bitwarden's servers are compromised, the encrypted vault can be subjected to offline brute-force attack against the master password alone.


### 3.4 Dashlane

**Key Derivation:**
- Uses Argon2d (not Argon2id -- slightly better GPU resistance, less side-channel resistance)
- Derives an AES-256 key from the master password
- Vault encrypted with AES-256-CBC-HMAC

**Architecture:**
- Zero-knowledge: server never sees master password or unencrypted data
- Device-level encryption + cloud storage for sync
- Specific Argon2d parameters not publicly documented in detail

Source: [Dashlane Security White Paper](https://www.dashlane.com/download/whitepaper-en.pdf), [Dashlane Zero-Knowledge](https://www.dashlane.com/resources/dashlane-zero-knowledge-security)


### 3.5 age Encryption

**Passphrase Mode:**

age uses scrypt for passphrase-based encryption:

```
Parameters: N = 2^18 (262,144), r = 8, p = 1
Memory: 128 * 262144 * 8 = 256 MiB
Salt: 16 random bytes from CSPRNG
Key: scrypt(passphrase, "age-encryption.org/v1/scrypt" || salt, N, r, p, 32)
```

The derived 32-byte key encrypts the file key using ChaCha20-Poly1305.

**Limitations for SIGIL's Use Case:**

1. **Non-tunable parameters**: The work factor is hardcoded at `logN=18`. The Rust `age` crate allows setting it programmatically, but the CLI does not expose this.
2. **scrypt only**: No Argon2id option. scrypt has known ASIC implementations (Litecoin mining).
3. **Single recipient per file**: An scrypt recipient cannot be mixed with X25519 recipients in the same file.
4. **Maximum work factor**: Capped at `logN=22` (~512 MiB) for DoS protection during decryption.
5. **No composite keys**: No support for key file or hardware key as additional factors.

Source: [age scrypt.go](https://github.com/FiloSottile/age/blob/main/scrypt.go), [age specification](https://github.com/C2SP/C2SP/blob/main/age.md)

**Verdict:** age is excellent for simple file encryption but lacks the configurability needed for SIGIL's $1B brute-force-resistance target. SIGIL should implement its own vault format with Argon2id rather than wrapping age's passphrase mode.


### 3.6 LUKS (Linux Unified Key Setup)

**Architecture:**

LUKS2 separates the volume (data encryption) key from the user key:

```
user_passphrase --> Argon2id(passphrase, salt, params) --> derived_key
derived_key XOR encrypted_volume_key --> volume_key
volume_key --> AES-XTS-plain64 (full disk encryption)
```

**Multiple Key Slots:**

LUKS supports up to 32 key slots. Each slot independently encrypts the same volume key:
- Slot 0: Passphrase (Argon2id)
- Slot 1: Key file
- Slot 2: TPM2 (via Clevis)
- Slot 3: FIDO2 token (via systemd-cryptenroll)

Each slot derives its own key independently and decrypts the same volume key. This means **any single slot** can unlock the volume (OR logic, not AND).

**Argon2id Default Parameters (cryptsetup 2.4.0+):**
- Memory: 1 GiB (1,048,576 KiB)
- Time: 4 iterations
- Parallelism: 4 threads

Source: [LUKS Security Analysis](https://dys2p.com/en/2023-05-luks-security.html), [LUKS Wikipedia](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup)

**TPM Integration (via Clevis or systemd-cryptenroll):**

```bash
# Bind LUKS slot to TPM2 PCRs 0,2,4,7
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0,2,4,7 /dev/sda2

# Bind with both TPM2 and passphrase (AND logic)
systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes /dev/sda2
```

When `--tpm2-with-pin=yes` is used, both the TPM and a PIN/passphrase are required (AND logic), providing true multi-factor.

**Relevance to SIGIL:**

LUKS's multi-slot architecture (OR logic for recovery, AND logic for security) is a good model. SIGIL could implement:
- Primary slot: Passphrase + Device Key (AND)
- Recovery slot: Recovery code (sufficient alone, but high-entropy)
- Hardware slot: YubiKey hmac-secret (composable with passphrase)

---

## Part 4: Device Attestation and Multi-Factor Unsealing

### 4.1 TPM 2.0

**Sealing/Unsealing Flow:**

```
1. tpm2_createprimary -C o -c primary.ctx
   (Create a primary key under the owner hierarchy)

2. tpm2_pcrread sha256:0,1,2,3,7
   (Read current PCR values)

3. tpm2_createpolicy --policy-pcr -l sha256:0,1,2,3,7 -L policy.dat
   (Create a policy requiring these exact PCR values)

4. tpm2_create -C primary.ctx -i secret.dat -u seal.pub -r seal.priv -L policy.dat
   (Seal the secret data under the PCR policy)

5. tpm2_load -C primary.ctx -u seal.pub -r seal.priv -c seal.ctx
   (Load the sealed object into the TPM)

6. tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3,7
   (Unseal -- only succeeds if current PCRs match the policy)
```

**PCR Registers and What They Measure:**

| PCR | Measurement |
|-----|-------------|
| 0 | BIOS firmware |
| 1 | BIOS configuration |
| 2 | Option ROMs |
| 3 | Option ROM configuration |
| 4 | MBR / boot loader |
| 7 | Secure Boot state |

**Limitation for SIGIL:**

TPM binding ties the vault to a **specific physical machine**. If the machine dies, the sealed key is irrecoverable. This makes TPM suitable as one factor in a multi-factor scheme (with recovery codes as backup) but not as the sole authentication method.

Source: [TPM2 Software Community - Disk Encryption](https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html), [Infineon TPM Sealing](https://community.infineon.com/t5/Blogs/Sealing-and-unsealing-data-in-TPM/ba-p/465547)


### 4.2 FIDO2/WebAuthn with hmac-secret

**The hmac-secret Extension (CTAP2):**

This is the most promising hardware key integration for SIGIL. The FIDO2 `hmac-secret` extension (and its WebAuthn counterpart, the PRF extension) allows a security key to derive a deterministic cryptographic secret **offline**, without any server.

**How It Works:**

1. **Credential Creation** (one-time setup):
   ```
   Authenticator generates and stores a PRF seed internally
   Returns: credential_id, public_key
   ```

2. **Secret Derivation** (each vault unlock):
   ```
   Client sends: credential_id, salt (application-defined)
   Authenticator computes: HMAC-SHA256(PRF_seed, salt)
   Returns: 32-byte derived secret
   ```

3. **Vault Encryption** (SIGIL integration):
   ```
   yubikey_secret = FIDO2_hmac_secret(credential_id, salt="sigil-vault-v1")
   vault_key = Argon2id(passphrase || yubikey_secret, salt, params)
   ```

**Security Properties:**
- PRF seed **never leaves the secure element** -- this is the root of trust
- Same inputs always produce the same output (deterministic)
- Different salts produce different outputs (domain separation)
- Phishing-resistant: bound to the relying party ID (rpId)
- No server required: entirely offline operation

**Domain Separation for Multiple Vaults:**
```
salt_vault_a = SHA-256("sigil/v1/vault/" || vault_id_a)
salt_vault_b = SHA-256("sigil/v1/vault/" || vault_id_b)
secret_a = FIDO2_hmac_secret(cred_id, salt_vault_a)  // different from secret_b
secret_b = FIDO2_hmac_secret(cred_id, salt_vault_b)
```

**Implementation with libfido2 (Rust Bindings):**

The `libfido2` C library (maintained by Yubico) provides the low-level CTAP2 interface. Rust bindings exist via the `libfido2` crate. The workflow:

1. Create a credential with `FIDO_EXT_HMAC_SECRET` enabled
2. Store the credential_id in the vault header
3. On unlock, perform an assertion with the salt to get the 32-byte secret
4. Use HKDF to derive the actual key material: `HKDF-SHA256(IKM=raw_secret, salt=vault_salt, info="AES-GCM-256-Key-v1")`
5. Securely wipe raw secret from memory

Source: [Yubico CTAP2 HMAC Secret Deep Dive](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html), [Yubico hmac-secret docs](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html)


### 4.3 Machine Identity / Device Fingerprint

**Components for Device Fingerprinting:**

| Component | Stability | Spoofing Difficulty | Uniqueness |
|-----------|-----------|--------------------| ------------|
| Motherboard UUID | High (survives OS reinstall) | Kernel-level | High |
| CPU ID (CPUID instruction) | Permanent | Requires VM | Moderate |
| Disk serial number | Until drive replacement | Kernel-level | High |
| MAC address | Until NIC replacement | Trivial (userspace) | High |
| TPM endorsement key | Permanent | Impossible (hardware) | High |
| Machine-ID (`/etc/machine-id`) | Until OS reinstall | Trivial (file edit) | High |

**Recommended Approach for SIGIL:**

Derive a device key by hashing multiple hardware identifiers:

```rust
device_key = HMAC-SHA256(
    key = "sigil-device-key-v1",
    data = motherboard_uuid || cpu_id || boot_disk_serial || tpm_ek_hash
)
```

**Spoofing Resistance:**
- Combining 3+ identifiers requires kernel-level access to spoof all simultaneously
- An attacker who has kernel-level access on the target machine already has access to the decrypted vault in memory
- Therefore, device fingerprinting provides defense against **offline attacks on the vault file** (e.g., stolen from git), not against attackers with root on the device

**Practical Concern:**
- Hardware changes (new disk, new NIC) will change the fingerprint
- SIGIL needs a recovery mechanism when hardware changes
- Solution: Device key is one factor in a multi-factor scheme; passphrase + recovery code can re-enroll a new device

Source: [HWID Explanation](https://licenseseat.com/what-is-hwid)


### 4.4 TOTP as an Unsealing Factor

**Challenge: TOTP Values Change Every 30 Seconds**

Standard TOTP (RFC 6238) produces a 6-8 digit code that changes every 30 seconds. This makes it unsuitable as a direct input to key derivation because:
- The time window means the KDF input is predictable (only ~10^6 possibilities per 30-second window)
- An attacker who knows the TOTP seed can compute all future values
- Clock skew between devices causes unlock failures

**MFKDF Approach (Nair & Song, USENIX Security 2023):**

The MFKDF (Multi-Factor Key Derivation Function) solves this by incorporating TOTP into key derivation:

1. During setup, the current TOTP value is used alongside other factors to derive the key
2. An **encrypted envelope** of the TOTP seed is stored alongside the vault, encrypted with a key derived from the other factors
3. On subsequent unlocks:
   - User provides passphrase + current TOTP code
   - The system uses the TOTP code to help derive the key
   - If the TOTP code is correct, the derived key matches and decryption succeeds
   - The TOTP seed envelope is re-encrypted with the updated TOTP value for next time

This provides a **10^6x multiplier** on brute-force difficulty (~20 bits of additional entropy per TOTP factor) with essentially zero additional latency.

Source: [MFKDF Paper](https://arxiv.org/abs/2208.05586), [MFKDF.com](https://mfkdf.com)

**Simpler Approach for SIGIL:**

Rather than implementing full MFKDF, SIGIL could use TOTP as a secondary factor via the following scheme:

```
totp_secret = stored_in_vault_metadata (encrypted with passphrase-derived key)
totp_code = user_input (6 digits)
if TOTP_verify(totp_secret, totp_code):
    allow_vault_access()
else:
    deny()
```

This uses TOTP as an **authentication gate** rather than a **key derivation input**. It is simpler but provides less cryptographic benefit -- the vault is still decryptable with the passphrase alone, and TOTP only provides a software check, not a cryptographic one.

**Recommendation:** Use FIDO2 hmac-secret (hardware-bound, deterministic) rather than TOTP for vault unsealing. TOTP is better suited as a stored secret within the vault, not as an unsealing factor.


### 4.5 Recovery Codes

**Best Practices:**

| Property | Recommendation |
|----------|---------------|
| Length | 16-20 characters |
| Alphabet | Base32 or alphanumeric (case-insensitive) |
| Entropy | Minimum 80 bits, recommended 128 bits |
| Format | Grouped with dashes for readability: `PHUO-1DM4-647K-8I2N` |
| Count | 5-10 codes generated at setup |
| Usage | Single-use (invalidated after use) |
| Generation | CSPRNG (e.g., `getrandom()`) |

Source: [WorkOS Backup MFA Codes](https://workos.com/blog/how-backup-mfa-codes-work)

**SIGIL Recovery Code Design:**

```
Format: XXXX-XXXX-XXXX-XXXX-XXXX (20 chars, Base32, 100 bits entropy)
Usage: Each code, when provided, can derive the vault master key independently
Storage: Recovery codes are hashed (Argon2id) and stored in vault metadata
         during initial setup. The plaintext codes are shown once and must
         be written down.
```

**Implementation:**

```
recovery_code = random_base32(20)  // 100 bits entropy
recovery_key = Argon2id(recovery_code, vault_salt, m=1GiB, t=3, p=4)
encrypted_master_key = AES-256-GCM(recovery_key, master_key)
// Store encrypted_master_key in vault header as "recovery slot"
```

Each recovery code acts as an independent LUKS-style key slot that can decrypt the master key. Single-use is enforced by removing the corresponding slot after successful use and re-encrypting with a new recovery code.


### 4.6 Composite Key Scheme for SIGIL

**Combining Multiple Factors Using HKDF:**

HKDF (RFC 5869) is the standard mechanism for combining multiple key materials:

```
Step 1: Slow KDF on the password
  password_key = Argon2id(passphrase, salt, m=1GiB, t=3, p=4)

Step 2: Get device key
  device_key = HMAC-SHA256("sigil-device-v1", hw_fingerprint)

Step 3: Get hardware key (optional)
  yubikey_secret = FIDO2_hmac_secret(cred_id, "sigil-vault-v1")

Step 4: Combine via HKDF
  IKM = password_key || device_key || yubikey_secret
  PRK = HKDF-Extract(salt=vault_salt, IKM=IKM)
  vault_key = HKDF-Expand(PRK, info="sigil/v1/vault-key", len=32)
```

Source: [HKDF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), [Understanding HKDF](https://soatok.blog/2021/11/17/understanding-hkdf/)

**Security Properties of This Scheme:**

1. **Password compromise alone is insufficient**: Attacker also needs device key + YubiKey
2. **Device theft alone is insufficient**: Attacker also needs passphrase + YubiKey
3. **YubiKey theft alone is insufficient**: Attacker needs passphrase + device
4. **Git clone of vault alone is useless**: Attacker needs all three factors
5. **Any single factor can be weak**: The other factors compensate

**Entropy Addition:**

| Factor | Entropy | Source |
|--------|---------|--------|
| Passphrase (6 diceware words) | 77.5 bits | User memory |
| Device key (hardware fingerprint) | 128+ bits | Hardware |
| YubiKey hmac-secret | 256 bits | Secure element |
| **Combined** | **256 bits (HKDF output)** | All factors |

Even if the passphrase is only 40 bits (a weak password), the device key alone adds 128 bits, making the combined key infeasible to brute-force from the vault file alone.

**1Password-Inspired "Secret Key" for SIGIL:**

The most practical variant inspired by 1Password's 2SKD:

```
Setup:
  secret_key = CSPRNG(32)  // 256 bits, stored on device only
  vault_key = Argon2id(passphrase || secret_key, salt, m=1GiB, t=3, p=4)

Display to user:
  secret_key_display = Base32(secret_key)  // e.g., "SIGIL-A3SW-BYB7-98JR-YLJU-T423-TESQ-24TX-J5CC"

Recovery:
  User writes down secret_key_display on paper
  Can re-enter it on a new device to restore vault access
```

This achieves the core goal: **the vault file committed to git is computationally infeasible to brute-force**, regardless of passphrase strength, because the Secret Key (never in git) provides 256 bits of entropy. The passphrase provides defense against device theft.

---

## Summary: Recommended SIGIL Vault Encryption Design

### Encryption Stack

| Layer | Algorithm | Parameters |
|-------|-----------|------------|
| KDF | Argon2id | m=1 GiB, t=3, p=4 |
| Cipher | ChaCha20-Poly1305 or AES-256-GCM | 256-bit key, 96-bit nonce |
| Key Hierarchy | HKDF-SHA256 | Per-secret derived keys |
| Mnemonic Backup | BIP39-style 24-word phrase | 256 bits entropy |
| Key Splitting | Shamir's Secret Sharing (SLIP-39) | Configurable M-of-N |

### Authentication Factors

| Factor | Entropy | Required | Purpose |
|--------|---------|----------|---------|
| Passphrase | 65-90 bits | Yes | User-remembered secret |
| Device Key (1Password-style) | 256 bits | Yes | Makes git-committed vault infeasible to crack |
| FIDO2 hmac-secret | 256 bits | Optional | Hardware-bound factor |
| Recovery Codes | 100 bits each | Backup | Emergency recovery (5 single-use codes) |
| TPM Sealing | N/A | Optional | Device binding |

### Cost-to-Crack Estimates

| Scenario | Cost on AWS (p4d.24xlarge spot) |
|----------|-------------------------------|
| Passphrase only (6 diceware) + Argon2id 1GiB | ~$10^15 (one quadrillion) |
| Passphrase (weak, 40 bits) + Device Key (128 bits) + Argon2id 1GiB | > $10^50 (infeasible) |
| Passphrase (6 diceware) + Device Key + YubiKey + Argon2id 1GiB | Computationally impossible |
| Recovery code (100 bits) + Argon2id 1GiB | ~$10^30 (infeasible) |

The $1 billion target is achieved by the passphrase-only scenario with as few as 5 diceware words. Adding the Device Key (which never appears in git) makes it permanently infeasible regardless of passphrase strength.

---

Sources:
- [RFC 9106: Argon2](https://datatracker.ietf.org/doc/html/rfc9106)
- [GPU Cracking Benchmarks 2025](https://www.onlinehashcrack.com/guides/password-recovery/gpu-password-cracking-benchmarks-2025-rtx-vs-cpus.php)
- [Hashcat A100 Benchmark](https://gist.github.com/Chick3nman/d65bcd5c137626c0fcb05078bba9ca89)
- [Hashcat H100 Benchmark](https://gist.github.com/Chick3nman/e1417339accfbb0b040bcd0a0a9c6d54)
- [AWS p4d.24xlarge Pricing](https://instances.vantage.sh/aws/ec2/p4d.24xlarge)
- [scrypt Parameters (Filippo Valsorda)](https://words.filippo.io/the-scrypt-parameters/)
- [age scrypt.go Source](https://github.com/FiloSottile/age/blob/main/scrypt.go)
- [ElcomSoft LUKS2 GPU Analysis](https://blog.elcomsoft.com/2022/08/probing-linux-disk-encryption-luks2-argon-2-and-gpu-acceleration/)
- [LUKS Security Analysis](https://dys2p.com/en/2023-05-luks-security.html)
- [Balloon Hashing Paper](https://eprint.iacr.org/2016/027.pdf)
- [BIP-0039 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-0032 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [SLIP-0039 Specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [Shamir Secret Snakeoil](https://en.bitcoin.it/wiki/Shamir_Secret_Snakeoil)
- [FROST RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)
- [Post-Quantum Argon2](https://www.onlinehashcrack.com/guides/post-quantum-crypto/post-quantum-password-hashes-argon2-fate.php)
- [ML-KEM-768 (Filippo Valsorda)](https://words.filippo.io/mlkem768/)
- [KeePass Security](https://keepass.info/help/base/security.html)
- [KDBX4 Format](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/)
- [1Password Security Design](https://support.1password.com/1password-security/)
- [1Password Deep Keys](https://agilebits.github.io/security-design/deepKeys.html)
- [1Password SRP](https://1password.com/blog/developers-how-we-use-srp-and-you-can-too)
- [Bitwarden KDF Algorithms](https://bitwarden.com/help/kdf-algorithms/)
- [Bitwarden Security White Paper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Dashlane Security White Paper](https://www.dashlane.com/download/whitepaper-en.pdf)
- [age Specification](https://github.com/C2SP/C2SP/blob/main/age.md)
- [EFF Diceware Wordlists](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases)
- [TPM2 Disk Encryption](https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html)
- [Yubico CTAP2 hmac-secret](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html)
- [Yubico hmac-secret Docs](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html)
- [MFKDF (Nair & Song, USENIX Security 2023)](https://arxiv.org/abs/2208.05586)
- [MFKDF.com](https://mfkdf.com)
- [HKDF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
- [Understanding HKDF (Soatok)](https://soatok.blog/2021/11/17/understanding-hkdf/)
- [Ledger Academy: Multisig](https://www.ledger.com/academy/what-is-a-multisig-wallet)
- [Password Hashing Comparison 2025](https://www.onlinehashcrack.com/guides/password-recovery/gpu-password-cracking-benchmarks-2025-rtx-vs-cpus.php)
