"""evidence.signing.timestamp — RFC 3161 qualified timestamping.

Provides functions to request and verify RFC 3161 timestamps from a
Time Stamping Authority (TSA) for eIDAS-compliant audit evidence.
"""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)


async def request_timestamp(digest: bytes, tsa_url: str | None = None) -> bytes | None:
    """Request an RFC 3161 timestamp token from a TSA.

    Sends an HTTP POST with a TimeStampReq to the configured TSA and
    returns the DER-encoded TimeStampResp bytes.

    Args:
        digest: SHA-256 digest bytes (32 bytes) to timestamp.
        tsa_url: TSA endpoint URL. Defaults to CG_TSA_URL from config.

    Returns:
        DER-encoded TimeStampResp bytes, or None if the TSA is
        unavailable or the request fails.
    """
    from api.config import TSA_URL

    url = tsa_url or TSA_URL

    try:
        import rfc3161ng

        request = rfc3161ng.make_timestamp_request(data=None, digest=digest, hashname="sha256")
    except ImportError:
        # Fallback: build a minimal DER TimeStampReq manually using openssl
        logger.debug("rfc3161ng not available, using raw HTTP POST")
        request = _build_timestamp_request_openssl(digest)
        if request is None:
            logger.warning("Could not build TimeStampReq, skipping timestamp")
            return None

    import httpx

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                url,
                content=request,
                headers={"Content-Type": "application/timestamp-query"},
            )
            resp.raise_for_status()
            return resp.content
    except Exception:
        logger.warning("TSA request failed for %s", url, exc_info=True)
        return None


def _build_timestamp_request_openssl(digest: bytes) -> bytes | None:
    """Build a TimeStampReq using openssl ts command as fallback.

    Uses ``openssl ts -query`` to generate a DER-encoded TimeStampReq.
    The ``-cert`` flag requests the TSA certificate in the response.
    """
    try:
        result = subprocess.run(
            [
                "openssl",
                "ts",
                "-query",
                "-digest",
                digest.hex(),
                "-sha256",
                "-cert",
            ],
            capture_output=True,
            check=True,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def verify_timestamp(token: bytes, digest: bytes, ca_cert_path: str | None = None) -> bool:
    """Verify an RFC 3161 timestamp token against a digest.

    Args:
        token: DER-encoded TimeStampResp bytes.
        digest: Expected SHA-256 digest bytes.
        ca_cert_path: Path to CA certificate for TSA verification.

    Returns:
        True if the timestamp is valid for the given digest.
    """
    try:
        import rfc3161ng

        return rfc3161ng.check_timestamp(tst=token, digest=digest, hashname="sha256", nonce=None)
    except ImportError:
        pass

    # Fallback: openssl ts -verify
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(suffix=".tsr") as tsr_file:
            tsr_file.write(token)
            tsr_file.flush()

            cmd = [
                "openssl",
                "ts",
                "-verify",
                "-digest",
                digest.hex(),
                "-in",
                tsr_file.name,
            ]
            if ca_cert_path:
                cmd.extend(["-CAfile", ca_cert_path])

            result = subprocess.run(cmd, capture_output=True)
            return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        logger.warning("openssl not available for timestamp verification")
        return False
