#!/usr/bin/env python3
"""
Crash Verification Oracle for OpenLDAP Fuzzing

Takes crash inputs from OSS-Fuzz and verifies if they crash a real slapd.
"""

import socket
import subprocess
import tempfile
import time
import os
import sys
import shutil
from pathlib import Path


class SlapdVerifier:
    def __init__(self, slapd_path="/usr/sbin/slapd", timeout=5):
        self.slapd_path = slapd_path
        self.timeout = timeout
        self.port = 3899  # Non-privileged port for testing
        self.proc = None
        self.config_dir = None

    def _create_minimal_config(self):
        """Create minimal slapd config for crash verification."""
        self.config_dir = tempfile.mkdtemp(prefix="slapd_verify_")

        config = f"""
include /etc/ldap/schema/core.schema

pidfile     {self.config_dir}/slapd.pid
argsfile    {self.config_dir}/slapd.args

database    ldif
directory   {self.config_dir}/data
suffix      "dc=test,dc=com"
rootdn      "cn=admin,dc=test,dc=com"
rootpw      secret
"""
        config_path = os.path.join(self.config_dir, "slapd.conf")
        with open(config_path, 'w') as f:
            f.write(config)

        os.makedirs(os.path.join(self.config_dir, "data"))
        return config_path

    def start_slapd(self, use_asan=True):
        """Start slapd with ASan if available."""
        config_path = self._create_minimal_config()

        env = os.environ.copy()
        if use_asan:
            env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'

        cmd = [
            self.slapd_path,
            '-f', config_path,
            '-h', f'ldap://127.0.0.1:{self.port}/',
            '-d', '0',  # No debug output
        ]

        self.proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )

        # Wait for slapd to start
        time.sleep(1)
        return self.proc.poll() is None

    def stop_slapd(self):
        """Stop slapd and cleanup."""
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

        if self.config_dir:
            shutil.rmtree(self.config_dir, ignore_errors=True)
            self.config_dir = None

    def send_crash_input(self, data: bytes) -> dict:
        """
        Send raw data to slapd and check for crash.

        Returns dict with:
          - crashed: bool
          - error_msg: str or None
          - response: bytes or None
        """
        result = {
            'crashed': False,
            'error_msg': None,
            'response': None
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(('127.0.0.1', self.port))

            # Send the crash input
            sock.sendall(data)

            # Try to read response
            try:
                result['response'] = sock.recv(4096)
            except socket.timeout:
                pass  # No response is fine

            sock.close()

        except ConnectionRefusedError:
            result['error_msg'] = "Connection refused - slapd may have crashed"
            result['crashed'] = True
        except BrokenPipeError:
            result['error_msg'] = "Broken pipe - slapd crashed during send"
            result['crashed'] = True
        except Exception as e:
            result['error_msg'] = str(e)

        # Check if slapd process is still alive
        if self.proc and self.proc.poll() is not None:
            result['crashed'] = True
            stderr = self.proc.stderr.read().decode('utf-8', errors='replace')
            if 'ASAN' in stderr or 'AddressSanitizer' in stderr:
                result['error_msg'] = f"ASan detected: {stderr[:500]}"
            elif stderr:
                result['error_msg'] = f"slapd stderr: {stderr[:500]}"

        return result

    def verify_crash(self, crash_file: Path) -> dict:
        """
        Verify a single crash file.

        Returns dict with verification results.
        """
        with open(crash_file, 'rb') as f:
            crash_data = f.read()

        # Restart slapd for each test (clean state)
        self.stop_slapd()
        if not self.start_slapd():
            return {
                'file': str(crash_file),
                'verified': False,
                'error': 'Failed to start slapd'
            }

        result = self.send_crash_input(crash_data)

        return {
            'file': str(crash_file),
            'verified': result['crashed'],
            'server_crashed': result['crashed'],
            'error_msg': result['error_msg'],
            'input_size': len(crash_data)
        }


def classify_crash(crash_file: Path) -> str:
    """
    Determine which harness produced this crash based on filename.
    """
    name = crash_file.name.lower()
    if 'ber_decode' in name or 'ber_structure' in name:
        return 'liblber'  # Likely server-exploitable
    elif 'dn_parse' in name:
        return 'libldap_dn'  # Client-side
    elif 'url' in name:
        return 'libldap_url'  # Client-side only
    elif 'asn1' in name:
        return 'liblber'  # Likely server-exploitable
    return 'unknown'


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description='Verify OpenLDAP fuzzer crashes against real slapd'
    )
    parser.add_argument('crash_files', nargs='+', type=Path,
                       help='Crash input files to verify')
    parser.add_argument('--slapd', default='/usr/sbin/slapd',
                       help='Path to slapd binary (ASan-enabled preferred)')
    parser.add_argument('--output', '-o', type=Path,
                       help='Output JSON report file')

    args = parser.parse_args()

    verifier = SlapdVerifier(slapd_path=args.slapd)
    results = []

    try:
        for crash_file in args.crash_files:
            crash_type = classify_crash(crash_file)

            print(f"\n{'='*60}")
            print(f"Verifying: {crash_file.name}")
            print(f"Type: {crash_type}")

            if crash_type in ('libldap_url',):
                print("  SKIP: Client-only code path, not server-exploitable")
                results.append({
                    'file': str(crash_file),
                    'verified': False,
                    'skip_reason': 'Client-only code path'
                })
                continue

            result = verifier.verify_crash(crash_file)
            result['crash_type'] = crash_type
            results.append(result)

            if result['verified']:
                print(f"  VERIFIED: Crash reproduces on slapd!")
                print(f"    {result.get('error_msg', 'No details')}")
            else:
                print(f"  NOT VERIFIED: Did not crash slapd")

    finally:
        verifier.stop_slapd()

    # Summary
    verified = sum(1 for r in results if r.get('verified'))
    print(f"\n{'='*60}")
    print(f"SUMMARY: {verified}/{len(results)} crashes verified as server-exploitable")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Report written to: {args.output}")

    return 0 if verified == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
