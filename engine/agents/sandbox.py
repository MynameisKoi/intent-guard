"""Dynamic dry-run execution inside Docker (optional)."""

from __future__ import annotations

import logging
import subprocess

from config import settings

logger = logging.getLogger(__name__)


def run_sandbox_smoke(workspace_root: str) -> dict[str, str | bool]:
    """
    Best-effort `docker run` of SANDBOX_IMAGE with a short timeout.
    Returns structured status without failing the overall scan.
    """
    try:
        cmd = ["docker", "run", "--rm"]
        if settings.sandbox_network_none:
            # Safer default for third-party agent repos during dry-runs.
            cmd.extend(["--network", "none"])
        cmd.extend(
            [
                settings.sandbox_image,
                "python",
                "-c",
                "print('sandbox_ok')",
            ]
        )
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=min(settings.sandbox_timeout, 30),
        )
        ok = r.returncode == 0
        return {
            "ran": True,
            "ok": ok,
            "stdout": (r.stdout or "")[:2000],
            "stderr": (r.stderr or "")[:2000],
        }
    except FileNotFoundError:
        logger.info("docker CLI not found — skipping sandbox dry-run")
        return {"ran": False, "ok": False, "note": "docker not installed"}
    except subprocess.TimeoutExpired:
        return {"ran": True, "ok": False, "note": "timeout"}
    except Exception as e:
        logger.warning("sandbox: %s", e)
        return {"ran": False, "ok": False, "note": str(e)}
