# PQC TLS Configuration Checker

A Python tool to test TLS configurations for Post-Quantum Cryptography (PQC) support.

## Overview

This script uses OpenSSL to test remote servers and determine if they support and prioritize post-quantum cryptography (PQC) key exchange algorithms. With the advent of quantum computing, traditional cryptographic algorithms like RSA and ECC are at risk. This tool helps you assess whether your servers are quantum-resistant by analyzing the actual key exchange algorithms negotiated during TLS handshakes.

## Features

- Tests TLS connections for PQC support (requires TLS 1.3)
- Detects PQC key exchange mechanisms (X25519MLKEM768 and other hybrid algorithms)
- Identifies if PQC key exchange is used by the server
- Provides detailed recommendations for enabling PQC
- No external Python dependencies (uses Python standard library + OpenSSL)
- Simple CLI interface

**Note on Naming:** Kyber was renamed to ML-KEM (Module-Lattice Key Encapsulation Mechanism) when NIST standardized it in 2024. You'll see both names in the wild—they refer to the same algorithm. Older implementations use "Kyber" naming; newer ones use "ML-KEM".

## Installation

```bash
# Clone or download the script
chmod +x pqc_checker.py
```

## Requirements

- Python 3.7+ (3.8+ recommended)
- **OpenSSL command-line tools** (version 3.2+ recommended for full PQC support)
  - Most Linux/macOS systems have this pre-installed
  - Windows: Install from [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html) or use WSL
- No external Python packages required

## Quick Check

Before testing your own servers, verify your environment is set up correctly:

```bash
# Check your OpenSSL version (need 3.2+ for full PQC support)
openssl version

# Quick test against a known PQC-enabled site
./pqc_checker.py www.google.com

# Expected output should show X25519MLKEM768 support
```

If you see "✅ POST-QUANTUM CRYPTOGRAPHY IS SUPPORTED" when testing www.google.com, your OpenSSL setup is working correctly.

## Usage

### Basic Usage

```bash
# Test a domain
./pqc_checker.py example.com

# Test with custom port
./pqc_checker.py example.com -p 8443

# Test with verbose output
./pqc_checker.py example.com --verbose

# Test with URL
./pqc_checker.py https://example.com
```

### Command Line Options

```
positional arguments:
  host                  Hostname or URL to test

optional arguments:
  -h, --help            Show help message
  -p PORT, --port PORT  Port number (default: 443)
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds (default: 10)
  -v, --verbose         Show detailed connection information
```

### Exit Codes

- `0`: PQC is supported and prioritized
- `1`: PQC is not supported
- `2`: Connection error or server unreachable

## Post-Quantum Cryptography (PQC)

### What is PQC?

Post-quantum cryptography refers to cryptographic algorithms that are secure against attacks by quantum computers. In 2024, NIST standardized several PQC algorithms, including:

- **Kyber (ML-KEM)**: Key encapsulation mechanism for key exchange
- **Dilithium (ML-DSA)**: Digital signature algorithm
- **Falcon**: Alternative digital signature algorithm

### Why PQC Matters

1. **Quantum Threat**: Large-scale quantum computers could break current public-key cryptography
2. **Harvest Now, Decrypt Later**: Attackers are collecting encrypted data today to decrypt in the future
3. **Migration Time**: Transitioning to PQC takes time; early adoption is recommended
4. **Compliance**: Future regulations may require PQC support

### Hybrid Approaches

Current implementations use hybrid key exchange, combining classical and post-quantum algorithms:

- **X25519MLKEM768** (also called X25519Kyber768): Combines X25519 (classical) with ML-KEM-768 (PQC)
  - This is the most widely deployed PQC algorithm, used by Google, Cloudflare, and Chrome

Hybrid approaches ensure security even if one algorithm is compromised. Other variants like P-256Kyber512 and P-384Kyber768 exist but are not widely deployed in production.

## Enabling PQC on Your Server

### Prerequisites

- OpenSSL 3.2+ with PQC support
- Web server that supports TLS 1.3

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;

    # Enable TLS 1.3 (required for PQC)
    ssl_protocols TLSv1.3;

    # Prefer server cipher order
    ssl_prefer_server_ciphers on;

    # Enable PQC hybrid key exchange
    # Note: ssl_ecdh_curve configures key exchange groups (not just EC curves)
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;

    # Certificates
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
}
```

**Note:** Depending on your OpenSSL/Nginx version, you may need to use `X25519Kyber768` instead of `X25519MLKEM768`.

### Apache Configuration

```apache
<VirtualHost *:443>
    # Enable TLS 1.3 (required for PQC)
    SSLProtocol -all +TLSv1.3

    # Enable PQC hybrid key exchange
    SSLOpenSSLConfCmd Curves X25519MLKEM768:X25519:prime256v1

    # Honor server cipher order
    SSLHonorCipherOrder on

    # Certificates
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
</VirtualHost>
```

**Note:** Depending on your OpenSSL/Apache version, you may need to use `X25519Kyber768` instead of `X25519MLKEM768`.

### Upgrading OpenSSL for PQC Support

Check your OpenSSL version: `openssl version`

#### OpenSSL 3.2+ (Recommended)
**Native ML-KEM support included.** Just update OpenSSL to 3.2 or later:

```bash
# On most systems, use your package manager
# Ubuntu/Debian (when available):
sudo apt update && sudo apt upgrade openssl

# macOS with Homebrew:
brew upgrade openssl
```

#### OpenSSL 3.0-3.1 (Requires OQS Provider)
For older OpenSSL 3.x versions, you'll need the Open Quantum Safe (OQS) provider:

```bash
# Install liboqs (Open Quantum Safe library)
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/oqs ..
make && sudo make install

# Install OQS provider for OpenSSL
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build
sudo cmake --install build
```

#### OpenSSL 1.1.1 or Earlier
Not compatible with PQC. Upgrade to OpenSSL 3.2+.

## Examples

### Example 1: No PQC Support

```bash
$ ./pqc_checker.py example.com

======================================================================
PQC TLS Configuration Check: example.com:443
======================================================================

❌ NO POST-QUANTUM CRYPTOGRAPHY SUPPORT DETECTED

📋 RECOMMENDATIONS:
   1. Enable PQC hybrid key exchange algorithms:
      • X25519Kyber768 (X25519 + Kyber768) - RECOMMENDED
      ...

======================================================================
```

### Example 2: PQC Supported and Prioritized

```bash
$ ./pqc_checker.py www.google.com --verbose

======================================================================
PQC TLS Configuration Check: www.google.com:443
======================================================================

TLS Version: TLSv1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
Key Exchange: X25519MLKEM768
Supported Ciphers: TLS_AES_256_GCM_SHA384, ECDHE-ECDSA-CHACHA20-POLY1305

✅ POST-QUANTUM CRYPTOGRAPHY IS SUPPORTED AND PRIORITIZED

   TLS Version: TLSv1.3
   Cipher Suite: TLS_AES_256_GCM_SHA384
   Key Exchange: X25519MLKEM768
   PQC Algorithms: X25519MLKEM768

👍 EXCELLENT! Your server is quantum-resistant.

======================================================================
```

## Testing Your Own Server

After configuring PQC on your server:

```bash
# Test the configuration
./pqc_checker.py your-domain.com -v

# Verify PQC is prioritized
openssl s_client -connect your-domain.com:443 -tls1_3
```

## How It Works

The script uses OpenSSL's `s_client` command to establish a TLS 1.3 connection and extract:
- Protocol version
- Cipher suite used
- **Key exchange algorithm** (where PQC is implemented)

It parses the "Negotiated TLS1.3 group" field from the OpenSSL output, which contains the key exchange algorithm (e.g., X25519MLKEM768). **PQC key exchange is a TLS 1.3 feature**—it's negotiated via the `supported_groups` extension. TLS 1.2 uses a fundamentally different key exchange mechanism (baked into the cipher suite) and has no real-world PQC deployment.

## Limitations

1. **Client Support**: Testing is limited by your OpenSSL version. OpenSSL 3.2+ is recommended for detecting modern PQC algorithms like ML-KEM (Kyber). Older versions may not negotiate PQC even when the server supports it.

2. **Server-Side Selection**: Some servers (like Google) may only offer PQC to clients that advertise support. Your results depend on your OpenSSL capabilities.

3. **Ongoing Development**: PQC in TLS is actively evolving. New algorithms and implementations are being standardized and deployed.

## Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [Cloudflare PQC](https://www.cloudflare.com/learning/ssl/what-is-post-quantum-cryptography/)
- [Google Chrome PQC Rollout](https://security.googleblog.com/2023/08/toward-quantum-resilient-security-keys.html)

## Contributing

Issues and pull requests welcome!

## License

MIT License - Feel free to use and modify as needed.

## Security Note

This tool is for testing and educational purposes. Always follow your organization's security policies and consult with security professionals when implementing cryptographic changes.
