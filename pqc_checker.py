#!/usr/bin/env python3
"""
Post-Quantum Cryptography TLS Configuration Checker

This script tests TLS configurations of remote servers to determine
if they support and prioritize post-quantum cryptography (PQC) cipher suites.
"""

import ssl
import socket
import argparse
import sys
import subprocess
import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse


# PQC Key Exchange Mechanisms (KEMs)
PQC_KEMS = [
    'kyber',
    'mlkem',  # Module-Lattice-Based KEM (standardized name for Kyber)
    'x25519kyber768',
    'x25519mlkem768',
    'p256kyber512',
    'p384kyber768',
    'ntru',
    'saber',
    'frodo',
]

# PQC Signature Algorithms
PQC_SIGNATURES = [
    'dilithium',
    'falcon',
    'sphincs',
]

# TLS 1.3 Cipher Suites
TLS13_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_CCM_SHA256',
    'TLS_AES_128_CCM_8_SHA256',
]


@dataclass
class TLSTestResult:
    """Results from TLS configuration testing"""
    hostname: str
    port: int
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    key_exchange: Optional[str]
    supported_ciphers: List[str]
    pqc_supported: bool
    pqc_prioritized: bool
    pqc_kems: List[str]
    error: Optional[str]


class PQCChecker:
    """Main class for checking PQC support in TLS configurations"""

    def __init__(self, hostname: str, port: int = 443, timeout: int = 10):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def _is_pqc_related(self, text: str) -> bool:
        """Check if a cipher/algorithm name is PQC-related"""
        text_lower = text.lower()
        return any(pqc in text_lower for pqc in PQC_KEMS + PQC_SIGNATURES)

    def _test_connection(self, context: ssl.SSLContext) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Attempt a TLS connection with the given context
        Returns: (tls_version, cipher_suite, error)
        """
        sock = None
        ssl_sock = None
        try:
            sock = socket.create_connection((self.hostname, self.port), timeout=self.timeout)
            ssl_sock = context.wrap_socket(sock, server_hostname=self.hostname)

            tls_version = ssl_sock.version()
            cipher_suite = ssl_sock.cipher()[0] if ssl_sock.cipher() else None

            return tls_version, cipher_suite, None
        except ssl.SSLError as e:
            return None, None, str(e)
        except socket.timeout:
            return None, None, "Connection timeout"
        except socket.error as e:
            return None, None, f"Socket error: {e}"
        except Exception as e:
            return None, None, f"Unexpected error: {e}"
        finally:
            if ssl_sock:
                try:
                    ssl_sock.close()
                except:
                    pass
            if sock:
                try:
                    sock.close()
                except:
                    pass

    def _run_openssl_client(self, tls_version: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Run openssl s_client to get detailed TLS handshake information
        Returns: (tls_version, cipher_suite, key_exchange, error)
        """
        cmd = ['openssl', 's_client', '-connect', f'{self.hostname}:{self.port}', '-servername', self.hostname]

        # Add TLS version flag if specified
        if tls_version == '1.3':
            cmd.extend(['-tls1_3'])
        elif tls_version == '1.2':
            cmd.extend(['-tls1_2'])

        try:
            # Run openssl s_client with a timeout
            result = subprocess.run(
                cmd,
                input=b'',
                capture_output=True,
                timeout=self.timeout
            )

            output = result.stdout.decode('utf-8', errors='ignore') + result.stderr.decode('utf-8', errors='ignore')

            # Parse the output
            tls_ver = None
            cipher = None
            key_ex = None
            error_msg = None

            # Look for protocol version (matches both "Protocol : TLSv1.3" and "Protocol: TLSv1.3")
            protocol_match = re.search(r'Protocol\s*:\s*(\S+)', output)
            if protocol_match:
                tls_ver = protocol_match.group(1)

            # Look for cipher suite (matches both "Cipher : xxx" and "Cipher is xxx")
            cipher_match = re.search(r'Cipher\s+(?:is\s+)?(\S+)', output)
            if cipher_match and cipher_match.group(1) not in ['is', ':']:
                cipher = cipher_match.group(1)

            # Look for key exchange (Server Temp Key for TLS 1.2, or Negotiated TLS1.3 group for TLS 1.3)
            key_match = re.search(r'Server Temp Key:\s+(.+?)(?:\n|$)', output)
            if key_match:
                key_ex = key_match.group(1).strip()
            else:
                # TLS 1.3 uses "Negotiated TLS1.3 group" instead
                group_match = re.search(r'Negotiated TLS1\.3 group:\s+(.+?)(?:\n|$)', output)
                if group_match:
                    key_ex = group_match.group(1).strip()

            # Check for connection errors
            if 'connect:errno' in output or 'Connection refused' in output:
                error_msg = "Connection refused"
            elif result.returncode != 0 and not tls_ver:
                error_msg = "Failed to establish TLS connection"

            return tls_ver, cipher, key_ex, error_msg

        except subprocess.TimeoutExpired:
            return None, None, None, "Connection timeout"
        except FileNotFoundError:
            return None, None, None, "OpenSSL not found. Please install OpenSSL command-line tools."
        except Exception as e:
            return None, None, None, f"Error running OpenSSL: {e}"

    def check_pqc_support(self) -> TLSTestResult:
        """
        Check if the target server supports PQC key exchange algorithms
        """
        supported_ciphers = []
        pqc_kems = []
        first_successful_version = None
        first_successful_cipher = None
        first_key_exchange = None
        last_error = None

        # First try with TLS 1.3 (where PQC is most common)
        tls_version, cipher_suite, key_exchange, error = self._run_openssl_client('1.3')

        if tls_version and cipher_suite:
            first_successful_version = tls_version
            first_successful_cipher = cipher_suite
            first_key_exchange = key_exchange
            supported_ciphers.append(cipher_suite)

            # Check if the key exchange is PQC-related
            if key_exchange and self._is_pqc_related(key_exchange):
                pqc_kems.append(key_exchange)
        else:
            last_error = error

        # Also try TLS 1.2 for completeness
        tls_version12, cipher_suite12, key_exchange12, error12 = self._run_openssl_client('1.2')

        if tls_version12 and cipher_suite12:
            if not first_successful_version:
                first_successful_version = tls_version12
                first_successful_cipher = cipher_suite12
                first_key_exchange = key_exchange12

            if cipher_suite12 not in supported_ciphers:
                supported_ciphers.append(cipher_suite12)

            # Check TLS 1.2 key exchange for PQC
            if key_exchange12 and self._is_pqc_related(key_exchange12):
                if key_exchange12 not in pqc_kems:
                    pqc_kems.append(key_exchange12)
        else:
            if not last_error:
                last_error = error12

        # Determine if PQC is supported and prioritized
        pqc_supported = len(pqc_kems) > 0
        pqc_prioritized = pqc_supported and first_key_exchange and self._is_pqc_related(first_key_exchange)

        return TLSTestResult(
            hostname=self.hostname,
            port=self.port,
            tls_version=first_successful_version,
            cipher_suite=first_successful_cipher,
            key_exchange=first_key_exchange,
            supported_ciphers=supported_ciphers,
            pqc_supported=pqc_supported,
            pqc_prioritized=pqc_prioritized,
            pqc_kems=pqc_kems,
            error=last_error if not first_successful_version else None
        )


def generate_recommendations(result: TLSTestResult) -> List[str]:
    """Generate recommendations based on test results"""
    recommendations = []

    if result.error:
        recommendations.append(f"⚠️  Could not connect to {result.hostname}:{result.port}")
        recommendations.append(f"   Error: {result.error}")
        return recommendations

    if not result.pqc_supported:
        recommendations.append("❌ NO POST-QUANTUM CRYPTOGRAPHY SUPPORT DETECTED")
        recommendations.append("")
        recommendations.append("📋 RECOMMENDATIONS:")
        recommendations.append("   1. Enable PQC hybrid key exchange algorithms:")
        recommendations.append("      • X25519Kyber768 (X25519 + Kyber768) - RECOMMENDED")
        recommendations.append("      • P-256Kyber512 (P-256 + Kyber512)")
        recommendations.append("      • P-384Kyber768 (P-384 + Kyber768)")
        recommendations.append("")
        recommendations.append("   2. Ensure TLS 1.3 is enabled and prioritized")
        recommendations.append("")
        recommendations.append("   3. Update OpenSSL to version 3.2+ which includes:")
        recommendations.append("      • ML-KEM (Kyber) support")
        recommendations.append("      • Hybrid PQC key exchange")
        recommendations.append("")
        recommendations.append("   4. Configure your web server to prefer PQC ciphers:")
        recommendations.append("")
        recommendations.append("      Nginx example:")
        recommendations.append("      ssl_protocols TLSv1.3;")
        recommendations.append("      ssl_prefer_server_ciphers on;")
        recommendations.append("      ssl_ecdh_curve X25519Kyber768:X25519:prime256v1;")
        recommendations.append("")
        recommendations.append("      Apache example:")
        recommendations.append("      SSLProtocol -all +TLSv1.3")
        recommendations.append("      SSLOpenSSLConfCmd Curves X25519Kyber768:X25519:prime256v1")
        recommendations.append("")
        recommendations.append("   5. Consider using AWS KMS, Cloudflare, or other providers")
        recommendations.append("      that already support PQC")
        recommendations.append("")
        recommendations.append("⚠️  WHY THIS MATTERS:")
        recommendations.append("   • Quantum computers threaten current encryption methods")
        recommendations.append("   • 'Harvest now, decrypt later' attacks are already happening")
        recommendations.append("   • NIST has standardized PQC algorithms (2024)")
        recommendations.append("   • Early adoption prepares for post-quantum security")

    elif not result.pqc_prioritized:
        recommendations.append("⚠️  PQC SUPPORT DETECTED BUT NOT PRIORITIZED")
        recommendations.append("")
        recommendations.append("📋 RECOMMENDATIONS:")
        recommendations.append("   1. Configure server to PRIORITIZE PQC cipher suites")
        recommendations.append("   2. Ensure PQC algorithms appear first in cipher list")
        recommendations.append("   3. Use ssl_prefer_server_ciphers (Nginx) or")
        recommendations.append("      SSLHonorCipherOrder (Apache) to enforce preference")
        recommendations.append("")
        recommendations.append(f"   Current cipher in use: {result.cipher_suite}")
        recommendations.append(f"   PQC ciphers detected: {', '.join(result.pqc_kems)}")
    else:
        recommendations.append("✅ POST-QUANTUM CRYPTOGRAPHY IS SUPPORTED AND PRIORITIZED")
        recommendations.append("")
        recommendations.append(f"   TLS Version: {result.tls_version}")
        recommendations.append(f"   Cipher Suite: {result.cipher_suite}")
        if result.key_exchange:
            recommendations.append(f"   Key Exchange: {result.key_exchange}")
        recommendations.append(f"   PQC Algorithms: {', '.join(result.pqc_kems)}")
        recommendations.append("")
        recommendations.append("👍 EXCELLENT! Your server is quantum-resistant.")

    return recommendations


def print_results(result: TLSTestResult, verbose: bool = False):
    """Print formatted test results"""
    print(f"\n{'='*70}")
    print(f"PQC TLS Configuration Check: {result.hostname}:{result.port}")
    print(f"{'='*70}\n")

    if verbose and result.tls_version:
        print(f"TLS Version: {result.tls_version}")
        print(f"Cipher Suite: {result.cipher_suite}")
        if result.key_exchange:
            print(f"Key Exchange: {result.key_exchange}")
        if result.supported_ciphers:
            print(f"Supported Ciphers: {', '.join(result.supported_ciphers)}")
        print()

    recommendations = generate_recommendations(result)
    for rec in recommendations:
        print(rec)

    print(f"\n{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Test TLS configurations for Post-Quantum Cryptography support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://example.com:8443
  %(prog)s example.com -p 8443 -v
  %(prog)s multiple.com --timeout 5
        """
    )

    parser.add_argument('host', help='Hostname or URL to test')
    parser.add_argument('-p', '--port', type=int, default=443,
                       help='Port number (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed connection information')

    args = parser.parse_args()

    # Parse hostname from URL if needed
    hostname = args.host
    port = args.port

    if hostname.startswith('http://') or hostname.startswith('https://'):
        parsed = urlparse(hostname)
        hostname = parsed.hostname
        if parsed.port:
            port = parsed.port

    if not hostname:
        print("Error: Invalid hostname", file=sys.stderr)
        sys.exit(1)

    # Run the check
    checker = PQCChecker(hostname, port, args.timeout)
    result = checker.check_pqc_support()

    # Print results
    print_results(result, args.verbose)

    # Exit with appropriate code
    if result.error:
        sys.exit(2)
    elif not result.pqc_supported:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
