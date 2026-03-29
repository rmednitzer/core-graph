"""evidence.signing.sign — Evidence signing via cosign.

Computes SHA-256 hash of evidence artifacts and optionally signs them
using Sigstore cosign. Falls back gracefully if cosign is not installed.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SigningResult:
    """Result of an evidence signing operation."""

    sha256: str
    signature_path: str | None = None
    rekor_log_index: int | None = None
    cosign_available: bool = False


def _compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def sign_blob(
    file_path: str | Path | None = None,
    data: bytes | None = None,
) -> SigningResult:
    """Sign a file or raw bytes using cosign.

    Args:
        file_path: Path to the file to sign.
        data: Raw bytes to sign (alternative to file_path).

    Returns:
        SigningResult with hash, optional signature path, and Rekor index.
    """
    if file_path is not None:
        blob = Path(file_path).read_bytes()
    elif data is not None:
        blob = data
    else:
        raise ValueError("Either file_path or data must be provided")

    sha256 = _compute_sha256(blob)

    # Check if cosign is available
    cosign_bin = shutil.which("cosign")
    if cosign_bin is None:
        logger.warning("cosign not found in PATH; returning hash only")
        return SigningResult(sha256=sha256, cosign_available=False)

    # Write blob to temp file if only data was provided
    if file_path is None:
        import tempfile

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".blob")
        tmp.write(blob)
        tmp.close()
        target_path = tmp.name
    else:
        target_path = str(file_path)

    sig_path = f"{target_path}.sig"

    try:
        result = subprocess.run(
            [
                cosign_bin,
                "sign-blob",
                "--yes",
                "--output-signature",
                sig_path,
                target_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            logger.error("cosign sign-blob failed: %s", result.stderr)
            return SigningResult(sha256=sha256, cosign_available=True)

        # Try to extract Rekor log index from output
        rekor_index = None
        for line in result.stderr.splitlines() + result.stdout.splitlines():
            if "tlog entry created with index:" in line.lower():
                try:
                    rekor_index = int(line.strip().split(":")[-1].strip())
                except (ValueError, IndexError):
                    pass

        return SigningResult(
            sha256=sha256,
            signature_path=sig_path,
            rekor_log_index=rekor_index,
            cosign_available=True,
        )
    except subprocess.TimeoutExpired:
        logger.error("cosign sign-blob timed out")
        return SigningResult(sha256=sha256, cosign_available=True)
    except Exception:
        logger.exception("cosign sign-blob error")
        return SigningResult(sha256=sha256, cosign_available=True)
