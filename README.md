# ft_ssl_rsa

A C implementation of RSA asymmetric cryptography, extending the capabilities of the previous [ft_ssl_md5](https://github.com/jesuserr/42Cursus_ft_ssl_md5) and [ft_ssl_des](https://github.com/jesuserr/42Cursus_ft_ssl_des) projects by adding RSA key generation, key management, and public-key encryption/decryption, recreating the behavior of OpenSSL's `genrsa`, `rsa`, and `rsautl` commands.

## 📋 Project Overview

This is the third and final ft_ssl project in the 42 school Encryption & Security path. It builds directly on top of the two previous projects and adds asymmetric cryptography: **RSA** key generation with Miller-Rabin primality testing, PEM key parsing/serialization, and raw RSA encryption/decryption — all with full OpenSSL compatibility.

> ⚠️ **Security Notice:** This implementation uses 64-bit RSA keys, which are **cryptographically broken** by modern standards. A 64-bit modulus can be factored in seconds on consumer hardware. By contrast, current recommendations call for a minimum of **2048-bit** keys for general use, with **3072-bit or 4096-bit** keys preferred for long-term security (NIST, BSI). This project exists purely for educational purposes within the 42 school curriculum. **Never use 64-bit RSA keys to protect real data.**

## 🎯 Implemented Commands

| Command | Description |
|---------|-------------|
| `genrsa` | Generate a 64-bit RSA private key |
| `rsa` | Parse and inspect/convert RSA keys |
| `rsautl` | Encrypt or decrypt data with RSA keys |

All previously implemented commands (MD5, SHA-224/256/384/512, BASE64, DES, DES-ECB, DES-CBC, DES-CFB, DES-OFB) remain fully available.

## 🔧 Command Reference

### `ft_ssl genrsa`

Generates a 64-bit RSA private key and outputs it in PEM format.

```
./ft_ssl genrsa [-out <file>] [-verbose] [-test <n> <p>]
```

| Flag | Description |
|------|-------------|
| `-out <file>` | Write private key to file instead of stdout |
| `-verbose` | Print generation progress: `.` per p-candidate rejection, `,` per q-candidate rejection, `+` per passing Miller-Rabin round, `x` when p×q fails the 64-bit size requirement (mirrors OpenSSL output) |
| `-test <n> <p>` | Test if number `n` is prime at probability `p` (0–100) and exit |

```bash
# Generate key to stdout
./ft_ssl genrsa

# Generate key to file with verbose output
./ft_ssl genrsa -out key.pem -verbose

# Test primality of a number at 90% confidence
./ft_ssl genrsa -test 104729 90
```

### `ft_ssl rsa`

Reads, displays, converts, and validates RSA keys.

```
./ft_ssl rsa [-in <file>] [-out <file>] [-text] [-noout]
             [-modulus] [-check] [-pubin] [-pubout]
```

| Flag | Description |
|------|-------------|
| `-in <file>` | Input key file |
| `-out <file>` | Output key file |
| `-text` | Print key components in human-readable form |
| `-noout` | Suppress key output |
| `-modulus` | Print the modulus value |
| `-check` | Validate the RSA key: verifies p and q are prime, n = p×q, e = 65537, gcd(e,ϕ)=1, and that dmp1/dmq1/iqmp are consistent |
| `-pubin` | Read a public key as input |
| `-pubout` | Output a public key |

```bash
./ft_ssl rsa -in key.pem -text -noout          # print key details
./ft_ssl rsa -in key.pem -pubout -out pub.pem  # extract public key
./ft_ssl rsa -in key.pem -modulus -noout       # print modulus
./ft_ssl rsa -in key.pem -check                # validate key
```

### `ft_ssl rsautl`

Encrypts or decrypts data using RSA keys.

```
./ft_ssl rsautl [-in <file>] [-out <file>] [-inkey <file>]
                [-pubin] [-encrypt] [-decrypt] [-hexdump] [-crack]
```

| Flag | Description |
|------|-------------|
| `-in <file>` | Input file |
| `-out <file>` | Output file |
| `-inkey <file>` | RSA key file to use |
| `-pubin` | Input key is a public key |
| `-encrypt` | Encrypt with public key |
| `-decrypt` | Decrypt with private key |
| `-hexdump` | Print output as hex dump |
| `-crack` | Factor the 64-bit modulus using Pollard's rho (brute-force fallback) to recover plaintext (bonus) |

```bash
# Encrypt a message (plaintext limited to 8 bytes due to 64-bit modulus)
echo -n "jesuserr" | ./ft_ssl rsautl -encrypt -pubin -inkey pub.pem -out cipher.bin
# Decrypt the message
./ft_ssl rsautl -decrypt -inkey key.pem -in cipher.bin
# Cracking the ciphertext without the private key (bonus)
./ft_ssl rsautl -decrypt -inkey pub.pem -in cipher.bin -crack -pubin
```

## 🚀 Installation & Usage

```bash
git clone https://github.com/jesuserr/42Cursus_ft_ssl_rsa.git
cd 42Cursus_ft_ssl_rsa
```

### Compilation
```bash
make          # Compile the project
make clean    # Remove object files
make fclean   # Remove all build artifacts
make re       # Rebuild everything
make norm     # Check code style (42 norminette)
```

### End-to-End Example

```bash
./ft_ssl genrsa -out key.pem                                               # generate private key
./ft_ssl rsa -in key.pem -pubout -out pub.pem                              # extract public key
echo -n "Hi" | ./ft_ssl rsautl -encrypt -pubin -inkey pub.pem -out msg.enc # encrypt
./ft_ssl rsautl -decrypt -inkey key.pem -in msg.enc                        # decrypt
```

### Cross-compatibility with OpenSSL

> **Note:** Modern OpenSSL (1.x / 3.x) rejects 64-bit RSA keys as insecure and cannot interoperate with this project. Cross-testing requires **OpenSSL 0.9.8zh**, the last legacy release that still allows sub-512-bit key generation. See `openssl/notes.txt` for build instructions.

## 🏗️ Project Structure

```
.
├── Makefile
├── README.md                     # This file
├── libft/                        # Custom C library
└── srcs/
    ├── encode/                   # BASE64 (inherited)
    ├── encrypt/                  # DES cipher suite (inherited)
    ├── hash/                     # MD5 / SHA-2 family (inherited)
    ├── incs/                     # Header files
    ├── rsa/
    │   ├── rsa_genrsa.c          # Key generation + Miller-Rabin test
    │   ├── rsa_genrsa_maths.c    # Modular arithmetic (overflow-safe)
    │   ├── rsa_genrsa_format.c   # ASN.1 DER key serialization
    │   ├── rsa_rsa.c             # Key inspection and conversion
    │   ├── rsa_rsa_check.c       # Key consistency validation
    │   ├── rsa_rsautl.c          # Encryption / decryption
    │   └── rsa_utils.c           # PEM, BASE64 and shared helpers
    ├── main.c
    └── utils/                    # Bitwise, print helpers, etc...
```

## 🔬 Technical Implementation

### Key Generation (`genrsa`)

1. Two 32-bit random prime numbers **p** and **q** are generated by reading from `/dev/urandom` (quick pre-filter rejects even numbers and multiples of 3, 5, 7, 11)
2. Each candidate is tested with the **Miller-Rabin** primality algorithm (30 iterations by default, max 60 to avoid overflow)
3. The 64-bit modulus $n = p \times q$ is computed; the pair is rejected and regenerated if $n < 2^{63}$ or $p = q$, guaranteeing a true 64-bit modulus with distinct primes
4. Euler's totient $\phi(n) = (p-1)(q-1)$ is computed
5. Public exponent **e = 65537** is used (hardcoded standard)
6. Private exponent **d** is derived via the **Extended Euclidean Algorithm** as the modular inverse of e modulo ϕ(n)
7. CRT parameters **dmp1**, **dmq1**, and **iqmp** are computed for the ASN.1 encoding
8. The key is serialized as **ASN.1 DER** and output as **PEM** (BASE64 with header/footer)

### Modular Arithmetic

Since 64-bit operands are used, standard multiplication overflows 64 bits. Two key helpers are implemented without using 128-bit integers:
- **Modular multiplication** — binary method to compute `(a × b) mod n` safely
- **Modular exponentiation** — square-and-multiply method for fast `a^b mod n`

### Key Format (ASN.1 DER / PEM)

Keys follow the PKCS#1 structure encoded in ASN.1 DER format:

| Field | Private Key | Public Key |
|-------|-------------|------------|
| version | ✅ | — |
| modulus (n) | ✅ | ✅ |
| publicExponent (e) | ✅ | ✅ |
| privateExponent (d) | ✅ | — |
| prime1 (p) | ✅ | — |
| prime2 (q) | ✅ | — |
| exponent1 (dmp1) | ✅ | — |
| exponent2 (dmq1) | ✅ | — |
| coefficient (iqmp) | ✅ | — |

The serialized DER blob is BASE64-encoded and wrapped with standard PEM headers (`-----BEGIN/END RSA PRIVATE/PUBLIC KEY-----`).

### RSA Encryption / Decryption (`rsautl`)

Raw RSA textbook encryption: $c = m^e \mod n$  
Raw RSA textbook decryption: $m = c^d \mod n$

Since the modulus is 64 bits, the plaintext message is limited to 8 bytes.

### Bonus — Key Cracking (`-crack`)

The `-crack` flag on `rsautl` factors the 64-bit modulus **n** to recover **p** and **q**, then reconstructs the private key and decrypts the ciphertext. Two strategies are used in sequence:

| Strategy | How it works | Typical time |
|----------|-------------|--------------|
| **Pollard's rho** (primary) | Probabilistic cycle-detection algorithm — finds a non-trivial factor of n | A few **milliseconds** |
| **Brute-force trial division** (fallback) | Iterates from `UINT32_MAX / 2` upward until `n % i == 0` — guaranteed to find a factor but exhaustive | **4 – 8 seconds** |

Pollard's rho succeeds in the vast majority of cases almost instantly. The fallback is only reached when the algorithm cycles back to its starting point without finding a factor (i.e., `gcd(|x−y|, n) == n`), which in practice is rare but provably possible for certain prime pairs. The elapsed cracking time for whichever path was taken is printed on completion. Together, both approaches demonstrate why 64-bit RSA provides no real security.

## 📝 Notes on Code Style and Design

Some code writing decisions may look unusual or unnecessarily verbose at first glance. This is mainly due to the constraints imposed by the **42 Norminette**, the coding style enforced by 42 school projects. Among other rules, Norminette limits functions to a maximum of 25 lines (not totally respected within this project), forbids `for` loops, restricts variable declarations to the top of functions, and prohibits certain operators and constructs. These constraints can lead to design choices that would otherwise not be made in idiomatic C.

This project is the culmination of a three-part series — [ft_ssl_md5](https://github.com/jesuserr/42Cursus_ft_ssl_md5) → [ft_ssl_des](https://github.com/jesuserr/42Cursus_ft_ssl_des) → **ft_ssl_rsa** (this project). Each stage was deliberately architected with the next in mind, so that the codebase could grow incrementally without requiring a full rewrite. Reaching this final stage validates those earlier architectural decisions and rounds out a complete, self-contained OpenSSL reimplementation covering hashing, symmetric encryption, and asymmetric cryptography.

## 📝 License

This project is part of the 42 School curriculum and is intended for educational purposes.
