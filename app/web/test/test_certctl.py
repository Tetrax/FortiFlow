"""Focused PFX installation tests using disposable OpenSSL artifacts."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CERTCTL = ROOT / "scripts" / "certctl.py"
HOSTNAME = "fortiflow.test.lan"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if check and result.returncode:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def create_pfx(directory: Path, hostname: str, password: str) -> tuple[Path, Path]:
    certificate = directory / "certificate.pem"
    private_key = directory / "private-key.pem"
    bundle = directory / "certificate.pfx"
    password_file = directory / "password"
    password_file.write_text(password)
    password_file.chmod(0o600)
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(private_key), "-out", str(certificate), "-days", "2",
        "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}",
        "-addext", "extendedKeyUsage=serverAuth",
    )
    run(
        "openssl", "pkcs12", "-export", "-out", str(bundle),
        "-inkey", str(private_key), "-in", str(certificate),
        "-passout", f"file:{password_file}",
    )
    return bundle, password_file


def install(bundle: Path, password_file: Path, output: Path, hostname: str = HOSTNAME):
    return run(
        sys.executable, str(CERTCTL), "install", str(bundle),
        "--password-file", str(password_file), "--hostname", hostname,
        "--output-dir", str(output), check=False,
    )


class PfxInstallTests(unittest.TestCase):
    def test_installs_password_protected_pfx_with_restrictive_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, password_file = create_pfx(root, HOSTNAME, "fake-test-password")
            output = root / "certificates" / "active"

            result = install(bundle, password_file, output)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_symlink())
            self.assertEqual((output / "privkey.pem").stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.resolve().stat().st_mode & 0o777, 0o700)
            self.assertNotIn("fake-test-password", result.stdout + result.stderr)
            run("openssl", "x509", "-in", str(output / "fullchain.pem"), "-noout", "-checkhost", HOSTNAME)
            run("openssl", "pkey", "-in", str(output / "privkey.pem"), "-noout")

    def test_wrong_password_does_not_create_active_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, _ = create_pfx(root, HOSTNAME, "correct-test-password")
            wrong = root / "wrong-password"
            wrong.write_text("wrong-test-password")
            output = root / "certificates" / "active"

            result = install(bundle, wrong, output)

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertNotIn("wrong-test-password", result.stdout + result.stderr)

    def test_wrong_san_preserves_previous_valid_active_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_dir = root / "valid"
            invalid_dir = root / "invalid"
            valid_dir.mkdir()
            invalid_dir.mkdir()
            valid_bundle, valid_password = create_pfx(valid_dir, HOSTNAME, "valid-test-password")
            invalid_bundle, invalid_password = create_pfx(
                invalid_dir, "another.test.lan", "invalid-test-password"
            )
            output = root / "certificates" / "active"
            first = install(valid_bundle, valid_password, output)
            self.assertEqual(first.returncode, 0, first.stderr)
            target_before = os.readlink(output)
            certificate_before = (output / "fullchain.pem").read_bytes()

            failed = install(invalid_bundle, invalid_password, output)

            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(os.readlink(output), target_before)
            self.assertEqual((output / "fullchain.pem").read_bytes(), certificate_before)


if __name__ == "__main__":
    unittest.main()
