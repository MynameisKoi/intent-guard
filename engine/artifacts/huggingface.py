"""
Hugging Face model repository audit.

A model repo is fetched *without* its weights: the Hub API gives the file list,
card metadata, and Hugging Face's own security-scan status; small text files
(model card, configs, custom code, chat templates) are downloaded into a scratch
workspace so the regular IntentGuard pipeline (AST tracer + semantic LLM) can read
them; GGUF/safetensors headers are parsed in place with HTTP Range requests.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import requests

from config import get_settings
from engine.artifacts.byte_source import ByteSourceError, HttpRangeSource
from engine.artifacts.chat_template import check_chat_template
from engine.artifacts.gguf import inspect_gguf
from engine.artifacts.pickle_scan import inspect_pickle
from engine.artifacts.safetensors import inspect_safetensors
from engine.artifacts.types import ArtifactIssue, ArtifactReport

logger = logging.getLogger(__name__)

_HF_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?(?:huggingface\.co|hf\.co)/"
    r"(?!datasets/|spaces/|docs/|blog/|api/)"
    r"(?P<owner>[A-Za-z0-9][\w.-]*)/(?P<name>[\w.-]+)"
    r"(?:/(?:tree|blob|resolve)/(?P<rev>[^/?#]+)(?:/(?P<path>[^?#]+))?)?/?(?:[?#].*)?$",
    re.I,
)
_HF_SCHEME_RE = re.compile(r"^hf://(?P<owner>[A-Za-z0-9][\w.-]*)/(?P<name>[\w.-]+?)(?:@(?P<rev>[^/]+))?/?$", re.I)

_TEXT_SUFFIXES = (".md", ".json", ".py", ".jinja", ".txt", ".yaml", ".yml", ".sh", ".cfg", ".toml")
_PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib")
_EXEC_SUFFIXES = (".exe", ".msi", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".dmg", ".pkg", ".apk", ".jar", ".so", ".dylib", ".elf", ".appimage", ".deb", ".rpm")
_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".tar", ".tgz", ".tar.gz")
_SKIP_TEXT = ("tokenizer.json", "vocab.json", "merges.txt", "vocab.txt")

# Organizations commonly impersonated by typosquatting uploads.
KNOWN_ORGS = (
    "meta-llama", "mistralai", "google", "microsoft", "Qwen", "deepseek-ai", "openai", "nvidia",
    "tiiuae", "bigscience", "EleutherAI", "stabilityai", "black-forest-labs", "CohereForAI", "CohereLabs",
    "allenai", "ibm-granite", "apple", "facebook", "HuggingFaceTB", "HuggingFaceH4", "NousResearch",
    "TheBloke", "bartowski", "unsloth", "lmstudio-community", "ggml-org", "MaziyarPanahi", "mlx-community",
    "sentence-transformers", "BAAI", "intfloat", "moonshotai", "zai-org", "THUDM", "xai-org", "01-ai",
    "internlm", "openbmb", "amd", "Salesforce", "databricks", "Snowflake", "upstage", "LiquidAI",
)

# family keyword in repo name -> acceptable `model_type` / GGUF architecture prefixes
_FAMILIES: dict[str, tuple[str, ...]] = {
    "llama": ("llama", "mllama"), "mistral": ("mistral", "mistral3", "llama"), "mixtral": ("mixtral", "mistral"),
    "qwen": ("qwen",), "gemma": ("gemma",), "phi": ("phi",), "deepseek": ("deepseek",),
    "falcon": ("falcon",), "gpt2": ("gpt2",), "granite": ("granite",), "olmo": ("olmo",),
    "starcoder": ("starcoder", "gpt_bigcode"), "mamba": ("mamba",), "bert": ("bert", "roberta", "modernbert"),
    "t5": ("t5", "mt5", "umt5"), "whisper": ("whisper",), "glm": ("glm", "chatglm"),
}

_CARD_RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("card_pipe_to_shell", "high", "Model card tells users to pipe a download into a shell",
     re.compile(r"(?i)\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\biex\s*\(")),
    ("card_extra_index", "high", "Model card installs packages from a non-default package index",
     re.compile(r"(?i)pip3?\s+install[^\n]{0,200}--(?:extra-)?index-url\s+(?!https://download\.pytorch\.org)\S+")),
    ("card_executable_download", "high", "Model card links to an executable or script download",
     re.compile(r"(?i)https?://[^\s)\"'>]+\.(?:exe|msi|scr|bat|cmd|ps1|vbs|dmg|pkg|apk|sh|appimage)(?:\?[^\s)\"'>]*)?(?=[\s)\"'>]|$)")),
    ("card_url_shortener", "medium", "Model card hides destinations behind URL shorteners",
     re.compile(r"(?i)https?://(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|t\.ly)/\S+")),
    ("card_git_dependency", "medium", "Model card installs code straight from a git URL",
     re.compile(r"(?i)pip3?\s+install\s+[^\n]{0,80}git\+https?://(?!github\.com/huggingface/)\S+")),
    ("card_disable_safety", "medium", "Model card tells users to disable safety checks",
     re.compile(r"(?i)(?:weights_only\s*=\s*False|--no-verify|disable[_ ](?:antivirus|defender|security)|allow_pickle\s*=\s*True)")),
)


def parse_hf_target(target: str) -> tuple[str, str | None, str | None] | None:
    """Return (repo_id, revision, file_path) for a Hugging Face model URL / hf:// ref."""
    t = target.strip()
    m = _HF_URL_RE.match(t) or _HF_SCHEME_RE.match(t)
    if not m:
        return None
    d = m.groupdict()
    return f"{d['owner']}/{d['name']}", d.get("rev"), d.get("path")


def is_hf_target(target: str) -> bool:
    return parse_hf_target(target) is not None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_of(author: str) -> str | None:
    a = author.lower()
    for org in KNOWN_ORGS:
        o = org.lower()
        if a == o:
            return None
    for org in KNOWN_ORGS:
        o = org.lower()
        if len(o) >= 5 and (
            _levenshtein(a, o) <= (1 if len(o) < 8 else 2)
            or a.replace("-", "").replace("_", "") == o.replace("-", "").replace("_", "")
            or (a.startswith(o) and a[len(o):] in ("-official", "official", "-ai", "ai", "-hf", "hf", "-org"))
        ):
            return org
    return None


@dataclass
class HFContext:
    repo_id: str
    revision: str
    file_filter: str | None
    info: dict[str, Any]
    root: Path
    downloaded: list[str] = field(default_factory=list)
    reports: list[ArtifactReport] = field(default_factory=list)
    binary_paths: list[Path] = field(default_factory=list)


class HFClient:
    def __init__(self) -> None:
        s = get_settings()
        self.endpoint = s.hf_endpoint.rstrip("/")
        self.timeout = int(s.hf_timeout)
        self.session = requests.Session()
        self.headers = {"User-Agent": "IntentGuard-model-audit/1.0"}
        if s.hf_token:
            self.headers["Authorization"] = f"Bearer {s.hf_token}"

    def model_info(self, repo_id: str, revision: str | None) -> dict[str, Any]:
        path = f"/api/models/{repo_id}" + (f"/revision/{quote(revision, safe='')}" if revision else "")
        r = self.session.get(f"{self.endpoint}{path}", params={"blobs": "true"}, headers=self.headers, timeout=self.timeout)
        if r.status_code == 401:
            raise RuntimeError(f"Hugging Face repo {repo_id} is private or gated — set HF_TOKEN")
        if r.status_code == 404:
            raise RuntimeError(f"Hugging Face model {repo_id} not found")
        r.raise_for_status()
        return r.json()

    def security_status(self, repo_id: str) -> dict[str, Any] | None:
        try:
            r = self.session.get(
                f"{self.endpoint}/api/models/{repo_id}",
                params={"securityStatus": "true"},
                headers=self.headers,
                timeout=self.timeout,
            )
            if r.ok:
                return r.json().get("securityRepoStatus")
        except (requests.RequestException, ValueError):
            pass
        return None

    def file_url(self, repo_id: str, revision: str, path: str) -> str:
        return f"{self.endpoint}/{repo_id}/resolve/{quote(revision, safe='')}/{quote(path)}"

    def download(self, repo_id: str, revision: str, path: str, dest: Path, max_bytes: int) -> bool:
        with self.session.get(
            self.file_url(repo_id, revision, path), headers=self.headers, timeout=self.timeout, stream=True
        ) as r:
            if not r.ok:
                return False
            dest.parent.mkdir(parents=True, exist_ok=True)
            total = 0
            with dest.open("wb") as fh:
                for chunk in r.iter_content(1 << 16):
                    total += len(chunk)
                    if total > max_bytes:
                        fh.close()
                        dest.unlink(missing_ok=True)
                        return False
                    fh.write(chunk)
        return True


def _safe_rel(path: str) -> Path | None:
    parts = [p for p in PurePosixPath(path).parts if p not in ("", ".", "..", "/")]
    return Path(*parts) if parts else None


def _sibling_size(sib: dict[str, Any]) -> int | None:
    lfs = sib.get("lfs") or {}
    return sib.get("size") or lfs.get("size")


def fetch_hf_repo(target: str) -> HFContext:
    parsed = parse_hf_target(target)
    if not parsed:
        raise ValueError(f"not a Hugging Face model reference: {target}")
    repo_id, revision, file_filter = parsed
    s = get_settings()
    client = HFClient()
    info = client.model_info(repo_id, revision)
    revision = revision or info.get("sha") or "main"
    root = Path(tempfile.mkdtemp(prefix="ig_hf_"))
    ctx = HFContext(repo_id=repo_id, revision=revision, file_filter=file_filter, info=info, root=root)

    siblings = info.get("siblings") or []
    text_candidates = [
        sib for sib in siblings
        if sib.get("rfilename", "").lower().endswith(_TEXT_SUFFIXES)
        and PurePosixPath(sib["rfilename"]).name not in _SKIP_TEXT
        and (_sibling_size(sib) or 0) <= s.hf_max_text_file_bytes
    ]
    # Model card and configs first, then custom code, then everything else.
    def priority(sib: dict[str, Any]) -> tuple[int, str]:
        name = sib["rfilename"]
        if name == "README.md":
            return 0, name
        if name in ("config.json", "tokenizer_config.json", "generation_config.json", "adapter_config.json"):
            return 1, name
        if name.endswith((".py", ".jinja")):
            return 2, name
        return 3, name

    for sib in sorted(text_candidates, key=priority)[: s.hf_max_text_files]:
        rel = _safe_rel(sib["rfilename"])
        if rel is None:
            continue
        try:
            if client.download(repo_id, revision, sib["rfilename"], root / rel, s.hf_max_text_file_bytes):
                ctx.downloaded.append(rel.as_posix())
        except requests.RequestException as e:
            logger.debug("download failed for %s: %s", sib["rfilename"], e)

    ctx.reports.append(_audit_repo(ctx, client, siblings))
    ctx.reports.extend(_inspect_remote_weights(ctx, client, siblings))
    _pull_small_binaries(ctx, client, siblings)
    return ctx


def _audit_repo(ctx: HFContext, client: HFClient, siblings: list[dict[str, Any]]) -> ArtifactReport:
    info = ctx.info
    report = ArtifactReport(name=f"hf://{ctx.repo_id}", kind="huggingface_repo")
    card_data = info.get("cardData") or {}
    names = [sib.get("rfilename", "") for sib in siblings]
    lower = [n.lower() for n in names]
    author = info.get("author") or ctx.repo_id.split("/")[0]
    config = _load_json(ctx.root / "config.json")
    tok_cfg = _load_json(ctx.root / "tokenizer_config.json")
    gguf_meta = info.get("gguf") or {}

    report.summary = {
        "repo_id": ctx.repo_id,
        "revision": ctx.revision,
        "author": author,
        "created_at": info.get("createdAt"),
        "last_modified": info.get("lastModified"),
        "downloads": info.get("downloads"),
        "likes": info.get("likes"),
        "gated": info.get("gated"),
        "private": info.get("private"),
        "disabled": info.get("disabled"),
        "pipeline_tag": info.get("pipeline_tag") or card_data.get("pipeline_tag"),
        "library_name": info.get("library_name") or card_data.get("library_name"),
        "license": card_data.get("license"),
        "base_model": card_data.get("base_model"),
        "datasets": card_data.get("datasets"),
        "model_type": (config or {}).get("model_type") or gguf_meta.get("architecture"),
        "architectures": (config or {}).get("architectures"),
        "file_count": len(names),
        "weight_formats": sorted({n.rsplit(".", 1)[-1] for n in lower if n.endswith((".gguf", ".safetensors", *_PICKLE_SUFFIXES))}),
        "downloaded_text_files": ctx.downloaded[:60],
        "tags": (info.get("tags") or [])[:30],
    }

    # --- model card ---------------------------------------------------------
    card_path = ctx.root / "README.md"
    card = card_path.read_text(encoding="utf-8", errors="replace") if card_path.exists() else ""
    body = re.sub(r"^---\n.*?\n---\n", "", card, count=1, flags=re.S).strip()
    report.summary["card_chars"] = len(body)
    if len(body) < 300:
        report.add(ArtifactIssue(
            code="hf_missing_card",
            title="Model card is missing or nearly empty",
            description=(
                "The repository documents nothing about training data, intended use, limitations, or "
                "provenance. Undocumented models cannot be assessed for poisoning or misuse."
            ),
            severity="medium", owasp_id="LLM03", location="README.md",
        ))
    if not card_data.get("license") and not any(t.startswith("license:") for t in info.get("tags") or []):
        report.add(ArtifactIssue(
            code="hf_no_license", title="No license declared",
            description="The card declares no license, so usage rights and provenance are unclear.",
            severity="low", owasp_id="LLM03", location="README.md",
        ))
    for code, sev, title, rx in _CARD_RULES:
        m = rx.search(card)
        if m:
            report.add(ArtifactIssue(
                code=code, title=title,
                description=f"Found in the model card: “{m.group(0)[:200]}”. Instructions in a model card run on the reader's machine.",
                severity=sev,  # type: ignore[arg-type]
                owasp_id="LLM03", location="README.md",
            ))

    # --- identity / impersonation ------------------------------------------
    squat = typosquat_of(author)
    if squat:
        report.add(ArtifactIssue(
            code="hf_typosquat",
            title=f"Publisher name imitates “{squat}”",
            description=(
                f"The account “{author}” is a near-match for the well-known publisher “{squat}”. "
                "Typosquatted model repos are a documented malware distribution channel."
            ),
            severity="high", owasp_id="LLM03",
        ))
    claimed = {fam for fam in _FAMILIES if re.search(rf"(?<![a-z]){fam}", ctx.repo_id.split("/")[1].lower())}
    declared = str(report.summary.get("model_type") or "").lower()
    if claimed and declared:
        ok = any(declared.startswith(prefix) for fam in claimed for prefix in _FAMILIES[fam])
        known_other = any(declared.startswith(p) for prefs in _FAMILIES.values() for p in prefs)
        if not ok and known_other:
            report.add(ArtifactIssue(
                code="hf_identity_mismatch",
                title="Repository name and model architecture disagree",
                description=(
                    f"The name suggests {', '.join(sorted(claimed))} but the model declares "
                    f"architecture “{declared}”. The model may be mislabelled or substituted."
                ),
                severity="medium", owasp_id="LLM04",
            ))

    # --- custom code ---------------------------------------------------------
    py_files = [n for n in names if n.endswith(".py")]
    auto_map = {}
    for cfg in (config, tok_cfg):
        if isinstance(cfg, dict) and isinstance(cfg.get("auto_map"), dict):
            auto_map.update(cfg["auto_map"])
    if py_files or auto_map:
        remote_refs = [v for v in auto_map.values() if isinstance(v, str) and "--" in v]
        report.add(ArtifactIssue(
            code="hf_remote_code",
            title="Loading this model executes repository code (trust_remote_code)",
            description=(
                f"The repo ships {len(py_files)} Python file(s) "
                + (f"and an auto_map ({', '.join(list(auto_map)[:4])})" if auto_map else "")
                + ". transformers runs this code on load when trust_remote_code=True. "
                + (f"auto_map also pulls code from other repos: {', '.join(remote_refs[:3])}. " if remote_refs else "")
                + "The code is included in this scan's static analysis."
            ),
            severity="high", owasp_id="LLM03",
            evidence={"python_files": py_files[:20], "auto_map": auto_map},
        ))

    # --- serialization formats ----------------------------------------------
    pickles = [n for n in names if n.lower().endswith(_PICKLE_SUFFIXES) and not n.lower().endswith("training_args.bin")]
    has_safe = any(n.endswith((".safetensors", ".gguf")) for n in lower)
    if pickles:
        report.add(ArtifactIssue(
            code="hf_pickle_weights",
            title="Pickle-serialized weights present" + ("" if has_safe else " (no safe alternative)"),
            description=(
                f"{len(pickles)} pickle-format file(s) (e.g. {pickles[0]}) execute code when loaded. "
                + ("A safetensors/GGUF copy exists — load that instead." if has_safe else "No safetensors or GGUF copy exists.")
            ),
            severity="medium" if has_safe else "high", owasp_id="LLM03",
            evidence={"files": pickles[:20]},
        ))
    executables = [n for n in names if n.lower().endswith(_EXEC_SUFFIXES)]
    archives = [n for n in names if n.lower().endswith(_ARCHIVE_SUFFIXES)]
    if executables:
        report.add(ArtifactIssue(
            code="hf_executables",
            title="Model repository ships executables or scripts",
            description=f"Files such as {', '.join(executables[:5])} have no place in a model repo and are a malware vector.",
            severity="high", owasp_id="LLM03", evidence={"files": executables[:20]},
        ))
    if archives:
        report.add(ArtifactIssue(
            code="hf_archives",
            title="Opaque archives in model repository",
            description=f"Archives ({', '.join(archives[:5])}) hide their contents from the Hub's scanners.",
            severity="medium", owasp_id="LLM03",
        ))
    has_weights = any(n.endswith((".gguf", ".safetensors", ".onnx", ".mlmodel", ".tflite", ".h5", ".msgpack", *_PICKLE_SUFFIXES)) for n in lower)
    if not has_weights and "adapter_config.json" not in names:
        report.add(ArtifactIssue(
            code="hf_no_weights",
            title="Repository contains no model weights",
            description="A 'model' repo without weights is often a lure pointing users at external downloads or scripts.",
            severity="medium", owasp_id="LLM03",
        ))

    # --- Hugging Face's own scanners -----------------------------------------
    sec = client.security_status(ctx.repo_id)
    if sec is not None:
        report.summary["hub_security_scan"] = {"scans_done": sec.get("scansDone"), "files_with_issues": len(sec.get("filesWithIssues") or [])}
        for f in (sec.get("filesWithIssues") or [])[:20]:
            level = str(f.get("level", "")).lower()
            report.add(ArtifactIssue(
                code="hf_hub_scan_flag",
                title=f"Hugging Face security scanner flagged {f.get('path')}",
                description=f"Hub scan level “{level or 'unknown'}”: {json.dumps(f)[:400]}",
                severity="critical" if level in ("unsafe", "malicious") else "medium",
                owasp_id="LLM03", location=f.get("path"),
            ))

    # --- chat templates --------------------------------------------------------
    templates: list[tuple[str, str]] = []
    if isinstance(tok_cfg, dict):
        ct = tok_cfg.get("chat_template")
        if isinstance(ct, str):
            templates.append(("tokenizer_config.json:chat_template", ct))
        elif isinstance(ct, list):
            templates += [(f"tokenizer_config.json:chat_template[{t.get('name')}]", t.get("template", "")) for t in ct if isinstance(t, dict)]
    for rel in ctx.downloaded:
        if rel.endswith(".jinja"):
            templates.append((rel, (ctx.root / rel).read_text(encoding="utf-8", errors="replace")))
    if not templates and isinstance(gguf_meta.get("chat_template"), str):
        templates.append(("gguf:tokenizer.chat_template", gguf_meta["chat_template"]))
    for loc, tpl in templates:
        for issue in check_chat_template(tpl, location=loc):
            report.add(issue)
    return report


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _inspect_remote_weights(ctx: HFContext, client: HFClient, siblings: list[dict[str, Any]]) -> list[ArtifactReport]:
    s = get_settings()
    picks: list[dict[str, Any]] = []
    ggufs = sorted((x for x in siblings if x.get("rfilename", "").endswith(".gguf")), key=lambda x: _sibling_size(x) or 0)
    sts = [x for x in siblings if x.get("rfilename", "").endswith(".safetensors")]
    if ctx.file_filter:
        picks = [x for x in siblings if x.get("rfilename") == ctx.file_filter]
    else:
        # Smallest GGUF quant (same metadata, cheapest to sample) plus a spread of others.
        picks = ggufs[:1] + ggufs[-1:] if len(ggufs) > 1 else ggufs[:]
        picks += sts[:2]
        picks += [g for g in ggufs if g not in picks]
    reports = []
    for sib in picks[: s.hf_max_weight_headers]:
        path = sib["rfilename"]
        url = client.file_url(ctx.repo_id, ctx.revision, path)
        try:
            src = HttpRangeSource(
                url,
                headers=client.headers,
                size=_sibling_size(sib),
                max_bytes=int(s.gguf_max_header_bytes),
                timeout=client.timeout,
                session=client.session,
            )
            if path.endswith(".gguf"):
                rep = inspect_gguf(
                    src, name=path,
                    sample_tensors=min(int(s.weight_sample_tensors), 8),
                    sample_bytes=min(int(s.weight_sample_bytes), 16_384),
                )
            elif path.endswith(".safetensors"):
                rep = inspect_safetensors(src, name=path)
            else:
                continue
            rep.summary["bytes_fetched"] = src.bytes_fetched
            reports.append(rep)
        except (ByteSourceError, requests.RequestException) as e:
            reports.append(ArtifactReport(name=path, kind="remote_weight", error=str(e)))

    for sib in siblings:
        path = sib.get("rfilename", "")
        size = _sibling_size(sib) or 0
        if path.lower().endswith(_PICKLE_SUFFIXES) and 0 < size <= s.hf_max_pickle_download_bytes:
            dest = ctx.root / ".ig_pickles" / (_safe_rel(path) or Path("weights.bin"))
            try:
                if client.download(ctx.repo_id, ctx.revision, path, dest, s.hf_max_pickle_download_bytes):
                    reports.append(inspect_pickle(dest, name=path))
                    dest.unlink(missing_ok=True)
            except requests.RequestException as e:
                logger.debug("pickle download failed for %s: %s", path, e)
    return reports


def _pull_small_binaries(ctx: HFContext, client: HFClient, siblings: list[dict[str, Any]]) -> None:
    """Executables in a model repo get the same REA/triage treatment as in a code repo."""
    s = get_settings()
    for sib in siblings:
        path = sib.get("rfilename", "")
        size = _sibling_size(sib) or 0
        if not path.lower().endswith(_EXEC_SUFFIXES) or not (0 < size <= s.hf_max_pickle_download_bytes):
            continue
        rel = _safe_rel(path)
        if rel is None:
            continue
        dest = ctx.root / ".ig_binaries" / rel
        try:
            if client.download(ctx.repo_id, ctx.revision, path, dest, s.hf_max_pickle_download_bytes):
                ctx.binary_paths.append(dest)
        except requests.RequestException:
            continue
