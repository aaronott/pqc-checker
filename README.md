# PQC TLS Configuration Checker

A Python tool to test TLS configurations for Post-Quantum Cryptography (PQC) support.

## Overview

This script uses OpenSSL to test remote servers and determine if they support and prioritize post-quantum cryptography (PQC) key exchange algorithms. With the advent of quantum computing, traditional cryptographic algorithms like RSA and ECC are at risk. This tool helps you assess whether your servers are quantum-resistant by analyzing the actual key exchange algorithms negotiated during TLS handshakes.

## Features

- Tests TLS 1.2 and TLS 1.3 connections
- Detects PQC key exchange mechanisms (Kyber, ML-KEM, hybrid algorithms)
- Identifies if PQC ciphers are prioritized by the server
- Provides detailed recommendations for enabling PQC
- No external dependencies (uses Python standard library only)
- Simple CLI interface

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

- **X25519Kyber768**: Combines X25519 (classical) with Kyber768 (PQC)
- **P-256Kyber512**: Combines NIST P-256 with Kyber512
- **P-384Kyber768**: Combines NIST P-384 with Kyber768

This ensures security even if one algorithm is broken.

## Enabling PQC on Your Server

### Prerequisites

- OpenSSL 3.2+ with PQC support
- Web server that supports TLS 1.3

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;

    # Enable TLS 1.3
    ssl_protocols TLSv1.3;

    # Prefer server cipher order
    ssl_prefer_server_ciphers on;

    # Enable PQC hybrid key exchange
    ssl_ecdh_curve X25519Kyber768:X25519:prime256v1;

    # Certificates
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
}
```

### Apache Configuration

```apache
<VirtualHost *:443>
    # Enable TLS 1.3 only
    SSLProtocol -all +TLSv1.3

    # Enable PQC hybrid key exchange
    SSLOpenSSLConfCmd Curves X25519Kyber768:X25519:prime256v1

    # Honor server cipher order
    SSLHonorCipherOrder on

    # Certificates
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
</VirtualHost>
```

### Building OpenSSL with PQC Support

If your system's OpenSSL doesn't support PQC:

```bash
# Install liboqs (Open Quantum Safe library)
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/oqs ..
make && sudo make install

# Build OpenSSL with OQS provider
git clone https://github.com/openssl/openssl.git
cd openssl
./config --prefix=/opt/openssl-pqc
make && sudo make install
```

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

The script uses OpenSSL's `s_client` command to establish TLS connections and extract:
- Protocol version (TLS 1.2, TLS 1.3)
- Cipher suite used
- **Key exchange algorithm** (where PQC is implemented)

For TLS 1.3, it parses the "Negotiated TLS1.3 group" field which contains the key exchange algorithm (e.g., X25519MLKEM768). This is where post-quantum cryptography is implemented in modern TLS connections.

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
