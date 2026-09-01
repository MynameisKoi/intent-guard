"""Deterministic AST / manifest walking to build a graph topology and code bundle."""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import re
from pathlib import Path
from collections.abc import Callable
from typing import Any

from engine.agents.ingestion import Workspace
from engine.agents.manifest_parser import AgentMarkdownManifest
from engine.agents.scope import classify_rel
from schemas.graph_nodes import GraphEdge, GraphNode, TopologyPayload

logger = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)

_SENSITIVE = re.compile(r"\.ssh|/etc/passwd|password|token|api[_-]?key", re.I)
_TEST_PATH_RE = re.compile(
    r"(?i)(^|/)(tests?|testdata|fixtures?|mocks?)(/|$)|(^|/)conftest\.py$|(^|/)test_.*\.py$|(^|/)mock_.*\.py$"
)
_RISKY_SINK_RE = re.compile(
    r"(?i)(subprocess(\.|$)|os\.system|eval$|exec$|requests\.(post|put|get|delete)|httpx\.(post|put|get|delete)|openai|anthropic)"
)
_ENTRY_CALL_RE = re.compile(r"(?i)(input$|read|environ|getenv|request|argv)")
_LLM_CONTEXT_RE = re.compile(r"(?i)(prompt|system_prompt|messages?|context)")
_MARKDOWN_TOOL_RE = re.compile(
    r"(?i)\b(bash|shell|python|nmap|sqlmap|curl|wget|ssh|git|docker|kubectl|read_file|write_file|browser|terminal)\b"
)
_MARKDOWN_PERMISSION_RE = re.compile(
    r"(?i)\b(filesystem:(read|write)|environment:(read|write)|network|shell|browser|terminal|docker|git|exec)\b"
)
_HEADING_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+(.+?)\s*$")
_BULLET_RE = re.compile(r"(?m)^\s*[-*+]\s+(.+?)\s*$")
_PROMPTISH_PARAM_NAMES = frozenset(
    {
        "prompt",
        "messages",
        "user_input",
        "user_message",
        "input",
        "content",
        "arguments",
        "query",
        "text",
        "instruction",
    }
)
_SOURCE_LABELS = {
    "environment": "Environment (getenv / environ)",
    "network_in": "Network (HTTP read)",
    "stdin": "stdin / input()",
    "argv": "CLI args (sys.argv)",
    "mcp_prompt": "MCP / tool prompt input",
}
def _manifest_for_rel(ws: Workspace, rel: str) -> AgentMarkdownManifest | None:
    rel_norm = rel.replace("\\", "/")
    for m in ws.agent_manifests:
        if m.rel_path.replace("\\", "/") == rel_norm:
            return m
    return None


def _semantic_snippet_for_agent(m: AgentMarkdownManifest, rel: str) -> str:
    """Structured excerpt for the semantic LLM (full system prompt body, bounded)."""
    max_body = 48_000
    body = (m.system_prompt or "")[:max_body]
    tools_line = ", ".join(m.tools) if m.tools else "(none declared)"
    perms_s = json.dumps(m.permissions, default=str)[:4000] if m.permissions is not None else "null"
    model_s = m.model or ""
    return (
        f"=== AGENT MARKDOWN (natural-language instructions): {rel} ===\n"
        f"agent_name: {m.name}\n"
        f"model: {model_s}\n"
        f"tools_declared: [{tools_line}]\n"
        f"permissions:\n{perms_s}\n"
        f"\n--- system prompt / body ---\n{body}\n"
    )


def _trace_agent_markdown(
    m: AgentMarkdownManifest,
    rel: str,
    nid,
    seen_ids: set[str],
) -> TopologyPayload:
    """Graph topology for prompt-only agent Markdown (no Python AST)."""
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    file_id = nid("file", rel)
    if file_id not in seen_ids:
        seen_ids.add(file_id)
        nodes.append(GraphNode(id=file_id, label=rel, kind="file", path=rel))
    agent_id = nid("agent", rel, m.name)
    if agent_id not in seen_ids:
        seen_ids.add(agent_id)
        nodes.append(
            GraphNode(
                id=agent_id,
                label=m.name,
                kind="agent",
                path=rel,
                meta={
                    "agent_file": rel,
                    "model": m.model,
                    "tools": m.tools,
                    "permissions": m.permissions,
                    "system_prompt_chars": len(m.system_prompt or ""),
                },
            )
        )
    e0 = nid("edge", file_id, agent_id, "contains_ag")
    edges.append(GraphEdge(id=e0, source=file_id, target=agent_id, kind="contains"))
    for tool in m.tools:
        tid = nid("tool", rel, tool)
        if tid not in seen_ids:
            seen_ids.add(tid)
            nodes.append(GraphNode(id=tid, label=tool, kind="tool", path=rel, meta={"tool": tool}))
        eid = nid("edge", agent_id, tid, "REQUESTS_TOOL", tool)
        edges.append(
            GraphEdge(
                id=eid,
                source=agent_id,
                target=tid,
                kind="REQUESTS_TOOL",
                variable_name=tool,
                meta={"tool": tool},
            )
        )
    return TopologyPayload(nodes=nodes, edges=edges)


def _infer_markdown_agent_name(rel: str, text: str) -> str:
    m = _HEADING_RE.search(text)
    if m:
        return m.group(1).strip()[:120]
    return Path(rel).stem.replace("_", " ").replace("-", " ").strip() or "Markdown agent"


def _extract_markdown_tools(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _MARKDOWN_TOOL_RE.finditer(text):
        tool = m.group(1).lower()
        if tool not in seen:
            seen.add(tool)
            out.append(tool)
    return out[:15]


def _extract_markdown_permissions(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _MARKDOWN_PERMISSION_RE.finditer(text):
        perm = m.group(1).lower()
        if perm not in seen:
            seen.add(perm)
            out.append(perm)
    return out[:12]


def _extract_markdown_tasks(text: str) -> list[str]:
    items: list[str] = []
    for m in _HEADING_RE.finditer(text):
        head = m.group(1).strip()
        if len(head) >= 4 and not re.fullmatch(r"(?i)readme|overview|introduction|notes?", head):
            items.append(head)
    for m in _BULLET_RE.finditer(text):
        item = m.group(1).strip()
        if 6 <= len(item) <= 140:
            items.append(item)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        norm = re.sub(r"\s+", " ", item.lower())
        if norm in seen:
            continue
        seen.add(norm)
        deduped.append(item[:140])
        if len(deduped) >= 12:
            break
    return deduped


def _trace_markdown_intent(
    *,
    rel: str,
    text: str,
    nid,
    seen_ids: set[str],
) -> tuple[TopologyPayload, dict[str, Any]]:
    """
    Build an intent graph from Markdown-only repos:
    Agent -> Prompt -> Tasks, Tools, Permissions.
    """
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    file_id = nid("file", rel)
    if file_id not in seen_ids:
        seen_ids.add(file_id)
        nodes.append(GraphNode(id=file_id, label=rel, kind="file", path=rel))

    agent_name = _infer_markdown_agent_name(rel, text)
    agent_id = nid("md_agent", rel, agent_name)
    if agent_id not in seen_ids:
        seen_ids.add(agent_id)
        nodes.append(
            GraphNode(
                id=agent_id,
                label=agent_name,
                kind="agent",
                path=rel,
                meta={"derived_from_markdown": True},
            )
        )
    edges.append(GraphEdge(id=nid("edge", file_id, agent_id, "contains_md_agent"), source=file_id, target=agent_id, kind="contains"))

    prompt_body = text.strip()[:6000]
    prompt_id = nid("prompt", rel)
    if prompt_id not in seen_ids:
        seen_ids.add(prompt_id)
        nodes.append(
            GraphNode(
                id=prompt_id,
                label=f"Prompt: {agent_name}"[:120],
                kind="prompt",
                path=rel,
                meta={"chars": len(text), "excerpt": prompt_body[:400]},
            )
        )
    edges.append(GraphEdge(id=nid("edge", agent_id, prompt_id, "instructs"), source=agent_id, target=prompt_id, kind="INSTRUCTS"))

    tools = _extract_markdown_tools(text)
    permissions = _extract_markdown_permissions(text)
    tasks = _extract_markdown_tasks(text)

    for tool in tools:
        tid = nid("md_tool", rel, tool)
        if tid not in seen_ids:
            seen_ids.add(tid)
            nodes.append(GraphNode(id=tid, label=tool, kind="tool", path=rel, meta={"derived_from_markdown": True}))
        edges.append(
            GraphEdge(
                id=nid("edge", agent_id, tid, "DECLARES_TOOL", tool),
                source=agent_id,
                target=tid,
                kind="DECLARES_TOOL",
                variable_name=tool,
            )
        )

    for perm in permissions:
        pid = nid("md_permission", rel, perm)
        if pid not in seen_ids:
            seen_ids.add(pid)
            nodes.append(
                GraphNode(id=pid, label=perm, kind="permission", path=rel, meta={"derived_from_markdown": True})
            )
        edges.append(
            GraphEdge(
                id=nid("edge", agent_id, pid, "REQUESTS_PERMISSION", perm),
                source=agent_id,
                target=pid,
                kind="REQUESTS_PERMISSION",
                variable_name=perm,
            )
        )

    for task in tasks:
        tid = nid("md_task", rel, task)
        if tid not in seen_ids:
            seen_ids.add(tid)
            nodes.append(GraphNode(id=tid, label=task, kind="task", path=rel, meta={"derived_from_markdown": True}))
        edges.append(
            GraphEdge(
                id=nid("edge", prompt_id, tid, "DESCRIBES_TASK", task),
                source=prompt_id,
                target=tid,
                kind="DESCRIBES_TASK",
            )
        )

    summary = {"agent": agent_name, "tools": tools, "permissions": permissions, "tasks": tasks}
    return TopologyPayload(nodes=nodes, edges=edges), summary


_STDLIB_GROUPS = {
    "os",
    "json",
    "pathlib",
    "typing",
    "datetime",
    "re",
    "collections",
    "itertools",
    "functools",
    "subprocess",
    "urllib",
    "http",
    "logging",
}


def trace_dataflow(
    ws: Workspace,
    *,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    scan_id: str | None = None,
) -> tuple[TopologyPayload, str, list[dict[str, Any]]]:
    """
    trace_dataflow() — map symbols and rough dataflow for Neo4j + LLM input.

    Returns topology, concatenated code excerpt, structured path hints.
    """
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    snippets: list[str] = []
    path_hints: list[dict[str, Any]] = []

    seen_ids: set[str] = set()

    def nid(*parts: str) -> str:
        raw = "::".join(parts)
        h = hashlib.sha256(raw.encode()).hexdigest()[:12]
        return f"n_{h}"

    for fp in ws.files:
        try:
            rel = str(fp.relative_to(ws.root))
        except ValueError:
            rel = fp.name
        rel_norm = rel.replace("\\", "/")
        if _is_excluded_test_path(rel_norm):
            logger.debug("Skipping test path in topology: %s", rel_norm)
            continue
        scope = classify_rel(rel_norm)
        file_hints: list[dict[str, Any]] = []
        if fp.suffix == ".py":
            topo, text, hints = _trace_python_file(fp, rel, nid, seen_ids)
            nodes.extend(topo.nodes)
            edges.extend(topo.edges)
            snippets.append(f"=== {rel} ===\n{text}")
            file_hints.extend(hints)
        elif fp.suffix in (".md",):
            manifest = _manifest_for_rel(ws, rel)
            if manifest:
                topo_m = _trace_agent_markdown(manifest, rel, nid, seen_ids)
                nodes.extend(topo_m.nodes)
                edges.extend(topo_m.edges)
                snippets.append(_semantic_snippet_for_agent(manifest, rel))
                file_hints.append(
                    {
                        "file": rel,
                        "agent": manifest.name,
                        "tools": manifest.tools,
                        "note": "Prompt-only agent markdown (YAML manifest + system instructions)",
                    }
                )
            else:
                text = fp.read_text(encoding="utf-8", errors="replace")
                topo_md, summary = _trace_markdown_intent(rel=rel, text=text, nid=nid, seen_ids=seen_ids)
                nodes.extend(topo_md.nodes)
                edges.extend(topo_md.edges)
                snippets.append(f"=== {rel} ===\n{text[:8000]}")
                file_hints.append(
                    {
                        "file": rel,
                        "agent": summary["agent"],
                        "tools": summary["tools"],
                        "permissions": summary["permissions"],
                        "tasks": summary["tasks"],
                        "note": "Markdown intent graph derived from headings, tools, permissions, and prompt text",
                    }
                )
                if _SENSITIVE.search(text):
                    file_hints.append(
                        {"file": rel, "note": "Markdown references sensitive paths or credentials"}
                    )
        elif fp.suffix == ".json":
            try:
                data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            raw = json.dumps(data)[:4000]
            snippets.append(f"=== {rel} ===\n{raw}")
            if "mcp" in rel.lower() or "tools" in rel.lower():
                fu = GraphNode(
                    id=nid("file", rel),
                    label=rel,
                    kind="file",
                    path=rel,
                    meta={"type": "json"},
                )
                if fu.id not in seen_ids:
                    seen_ids.add(fu.id)
                    nodes.append(fu)
        else:
            if fp.suffix:
                msg = f"[Warning] Skipping unsupported file type: {rel}"
                logger.warning("%s", msg)
                if on_event:
                    ev: dict[str, Any] = {
                        "type": "trace_warning",
                        "message": msg,
                        "file": rel,
                        "extension": fp.suffix,
                    }
                    if scan_id:
                        ev["scan_id"] = scan_id
                    on_event(ev)

        for hint in file_hints:
            hint.setdefault("scope", scope)
        path_hints.extend(file_hints)

    code_bundle = "\n\n".join(snippets)[:120_000]
    if not nodes:
        # minimal placeholder graph
        root_id = nid("workspace", "root")
        nodes.append(
            GraphNode(id=root_id, label=ws.root.name or "workspace", kind="file", path=".", meta={})
        )
    topo = TopologyPayload(nodes=_dedupe_nodes(nodes), edges=_dedupe_edges(edges))
    return topo, code_bundle, path_hints


def _dedupe_nodes(nodes: list[GraphNode]) -> list[GraphNode]:
    seen: set[str] = set()
    out: list[GraphNode] = []
    for n in nodes:
        if n.id in seen:
            continue
        seen.add(n.id)
        out.append(n)
    return out


def _dedupe_edges(edges: list[GraphEdge]) -> list[GraphEdge]:
    seen: set[str] = set()
    out: list[GraphEdge] = []
    for e in edges:
        if e.id in seen:
            continue
        seen.add(e.id)
        out.append(e)
    return out


def _trace_python_file(
    path: Path, rel: str, nid, seen_ids: set[str]
) -> tuple[TopologyPayload, str, list[dict[str, Any]]]:
    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return TopologyPayload(nodes=[], edges=[]), source[:8000], []

    file_id = nid("file", rel)
    seen_ids.add(file_id)
    nodes = [GraphNode(id=file_id, label=rel, kind="file", path=rel)]
    edges: list[GraphEdge] = []
    hints: list[dict[str, Any]] = []
    risky_callers: set[str] = set()
    stdlib_nodes_added: set[str] = set()
    sink_node_ids: dict[str, str] = {}
    fn_lineno: dict[str, int] = {}
    fn_id_map: dict[str, str] = {}

    def ensure_external_node(kind_key: str, label: str, *, family: str = "sink") -> str:
        node_id = sink_node_ids.get(kind_key)
        if node_id:
            return node_id
        node_id = nid("external", kind_key)
        sink_node_ids[kind_key] = node_id
        if node_id not in seen_ids:
            seen_ids.add(node_id)
            nodes.append(GraphNode(id=node_id, label=label, kind="external", meta={"family": family}))
        return node_id

    source_registry: dict[str, str] = {}

    def ensure_source_node(source_key: str) -> str:
        node_id = source_registry.get(source_key)
        if node_id:
            return node_id
        node_id = nid("source", rel, source_key)
        source_registry[source_key] = node_id
        if node_id not in seen_ids:
            seen_ids.add(node_id)
            label = _SOURCE_LABELS.get(source_key, f"Source:{source_key}")
            nodes.append(
                GraphNode(
                    id=node_id,
                    label=label,
                    kind="source",
                    path=rel,
                    is_source=True,
                    meta={"source_key": source_key},
                )
            )
        return node_id

    source_adopters: set[str] = set()
    source_entry_fns: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            fid = nid(rel, "fn", node.name)
            fn_lineno[node.name] = node.lineno
            fn_id_map[node.name] = fid

        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if not name:
                continue
            src = _caller_function_id(tree, node, rel, nid, seen_ids)
            if _RISKY_SINK_RE.search(name):
                if src:
                    risky_callers.add(src)
                    if "subprocess" in name or "os.system" in name:
                        sink_id = ensure_external_node("subprocess", "subprocess/shell", family="shell")
                    elif "eval" in name or "exec" in name:
                        sink_id = ensure_external_node("eval", "eval/exec", family="code_exec")
                    else:
                        sink_id = ensure_external_node("http", "HTTP", family="network")
                    var_hint = None
                    if node.args and isinstance(node.args[0], ast.Name):
                        var_hint = node.args[0].id
                    eid = nid("edge", src, sink_id, "sink", var_hint or "")
                    edges.append(
                        GraphEdge(
                            id=eid,
                            source=src,
                            target=sink_id,
                            kind="flows_to",
                            variable_name=var_hint,
                            meta={"sink_call": name},
                        )
                    )
                    hints.append(
                        {
                            "from_function": src,
                            "to": name,
                            "lineno": getattr(node, "lineno", None),
                            "note": "Call reaches high-risk sink",
                        }
                    )
            elif src and (_ENTRY_CALL_RE.search(name) or _LLM_CONTEXT_RE.search(name)):
                risky_callers.add(src)
                hints.append(
                    {
                        "from_function": src,
                        "to": name,
                        "lineno": getattr(node, "lineno", None),
                        "note": "Potential entry/context value in dataflow",
                    }
                )
            if "." in name:
                module_root = name.split(".", 1)[0]
                if module_root in _STDLIB_GROUPS and src:
                    risky_callers.add(src)
                    std_id = nid("stdlib", module_root)
                    if std_id not in stdlib_nodes_added:
                        stdlib_nodes_added.add(std_id)
                        seen_ids.add(std_id)
                        nodes.append(
                            GraphNode(
                                id=std_id,
                                label=f"stdlib:{module_root}",
                                kind="external",
                                meta={"family": "stdlib", "module": module_root},
                            )
                        )
                    use_var = None
                    if node.args and isinstance(node.args[0], ast.Name):
                        use_var = node.args[0].id
                    eid = nid("edge", src, std_id, "stdlib", use_var or "")
                    edges.append(
                        GraphEdge(
                            id=eid,
                            source=src,
                            target=std_id,
                            kind="uses",
                            variable_name=use_var,
                        )
                    )

    for fn_node in ast.walk(tree):
        if not isinstance(fn_node, ast.FunctionDef):
            continue
        fid = nid(rel, "fn", fn_node.name)
        if _is_entry_handler_function(fn_node):
            source_entry_fns.add(fid)
            risky_callers.add(fid)
            for a in (
                list(fn_node.args.posonlyargs)
                + list(fn_node.args.args)
                + list(fn_node.args.kwonlyargs)
            ):
                if a.arg.lower() in _PROMPTISH_PARAM_NAMES:
                    mcp_id = ensure_source_node("mcp_prompt")
                    eid = nid("edge", mcp_id, fid, "param", a.arg)
                    edges.append(
                        GraphEdge(
                            id=eid,
                            source=mcp_id,
                            target=fid,
                            kind="flows_to",
                            variable_name=a.arg,
                            meta={"source_key": "mcp_prompt"},
                        )
                    )
                    source_adopters.add(fid)
        for st in _flatten_stmts(fn_node.body):
            if isinstance(st, ast.Return) and st.value is not None:
                sk_ret = _expr_source_kind(st.value)
                if sk_ret:
                    src_nid = ensure_source_node(sk_ret)
                    source_adopters.add(fid)
                    eid = nid("edge", src_nid, fid, sk_ret, "return")
                    edges.append(
                        GraphEdge(
                            id=eid,
                            source=src_nid,
                            target=fid,
                            kind="flows_to",
                            variable_name="return",
                            meta={"source_key": sk_ret},
                        )
                    )
                continue

            vars_tz: list[str] = []
            value: ast.expr | None = None
            if isinstance(st, ast.Assign):
                value = st.value
                for t in st.targets:
                    vars_tz.extend(_target_names(t))
            elif isinstance(st, ast.AnnAssign) and st.value is not None:
                value = st.value
                vars_tz.extend(_target_names(st.target))
            else:
                continue
            sk = _expr_source_kind(value)
            if not sk or not vars_tz:
                continue
            src_nid = ensure_source_node(sk)
            source_adopters.add(fid)
            for vn in vars_tz[:4]:
                eid = nid("edge", src_nid, fid, sk, vn)
                edges.append(
                    GraphEdge(
                        id=eid,
                        source=src_nid,
                        target=fid,
                        kind="flows_to",
                        variable_name=vn,
                        meta={"source_key": sk},
                    )
                )

    for _sk, src_id in source_registry.items():
        eid = nid("edge", file_id, src_id, "contains_src", _sk)
        edges.append(GraphEdge(id=eid, source=file_id, target=src_id, kind="contains"))

    keep_fn_ids = risky_callers | source_entry_fns | source_adopters
    for fn_name, fid in fn_id_map.items():
        if fid not in keep_fn_ids:
            continue
        if fid not in seen_ids:
            seen_ids.add(fid)
        nodes.append(
            GraphNode(
                id=fid,
                label=fn_name,
                kind="function",
                path=rel,
                is_source=fid in source_entry_fns,
                meta={"lineno": fn_lineno.get(fn_name, 0), "pruned": True},
            )
        )
        eid = nid("edge", file_id, fid, "contains")
        edges.append(GraphEdge(id=eid, source=file_id, target=fid, kind="contains"))

    for m in _URL_RE.finditer(source):
        hints.append({"url": m.group(0)[:200], "file": rel})
    if _SENSITIVE.search(source):
        hints.append({"file": rel, "note": "Sensitive path or secret pattern"})

    return TopologyPayload(nodes=nodes, edges=edges), source[:12000], hints


def _call_name(func: ast.expr | None) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        cur: ast.expr | None = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _decorator_name(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return _call_name(dec)
    if isinstance(dec, ast.Call):
        return _call_name(dec.func)
    return None


def _expr_attribute_chain(expr: ast.expr | None) -> str | None:
    if expr is None:
        return None
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _expr_attribute_chain(expr.value)
        return f"{base}.{expr.attr}" if base else expr.attr
    return None


def _flatten_stmts(body: list[ast.stmt]) -> list[ast.stmt]:
    out: list[ast.stmt] = []
    for st in body:
        out.append(st)
        if isinstance(st, ast.If):
            out.extend(_flatten_stmts(st.body))
            out.extend(_flatten_stmts(st.orelse))
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            out.extend(_flatten_stmts(st.body))
            out.extend(_flatten_stmts(st.orelse))
        elif isinstance(st, ast.While):
            out.extend(_flatten_stmts(st.body))
            out.extend(_flatten_stmts(st.orelse))
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            out.extend(_flatten_stmts(st.body))
        elif isinstance(st, ast.Try):
            out.extend(_flatten_stmts(st.body))
            for h in st.handlers:
                out.extend(_flatten_stmts(h.body))
            out.extend(_flatten_stmts(st.orelse))
            out.extend(_flatten_stmts(st.finalbody))
        elif isinstance(st, ast.Match):
            for c in st.cases:
                out.extend(_flatten_stmts(c.body))
    return out


def _target_names(tgt: ast.expr) -> list[str]:
    if isinstance(tgt, ast.Name):
        return [tgt.id]
    if isinstance(tgt, ast.Tuple) or isinstance(tgt, ast.List):
        names: list[str] = []
        for elt in tgt.elts:
            names.extend(_target_names(elt))
        return names
    if isinstance(tgt, ast.Starred):
        return _target_names(tgt.value)
    if isinstance(tgt, ast.Subscript):
        return _target_names(tgt.value)
    if isinstance(tgt, ast.Attribute):
        return [tgt.attr]
    return []


def _expr_source_kind(expr: ast.expr | None) -> str | None:
    """Return a canonical source key if expr reads untrusted external data."""
    if expr is None:
        return None
    if isinstance(expr, ast.Subscript):
        ch = _expr_attribute_chain(expr.value)
        if ch:
            if "argv" in ch:
                return "argv"
            if "environ" in ch.lower():
                return "environment"
        return None
    if isinstance(expr, ast.Call):
        cname = (_call_name(expr.func) or "").lower()
        if cname == "input" or cname.endswith(".input"):
            return "stdin"
        if "getenv" in cname or cname.endswith(".getenv"):
            return "environment"
        if "requests.get" in cname or (cname.startswith("requests.") and cname.endswith(".get")):
            return "network_in"
        if "httpx.get" in cname or (cname.startswith("httpx.") and cname.endswith(".get")):
            return "network_in"
        if "urlopen" in cname:
            return "network_in"
        if isinstance(expr.func, ast.Attribute) and expr.func.attr in ("read", "readline", "readlines"):
            inner = _expr_attribute_chain(expr.func.value)
            if inner and "stdin" in inner:
                return "stdin"
        for arg in expr.args:
            sk = _expr_source_kind(arg)
            if sk:
                return sk
        for kw in expr.keywords or []:
            sk = _expr_source_kind(kw.value)
            if sk:
                return sk
        return None
    if isinstance(expr, ast.Attribute):
        ch = _expr_attribute_chain(expr)
        if ch and (ch.endswith("environ") or ".environ" in ch.lower()):
            return "environment"
        return None
    return None


def _is_entry_handler_function(fn: ast.FunctionDef) -> bool:
    if fn.name in ("main", "cli", "run", "handler", "app", "lambda_handler"):
        return True
    for dec in fn.decorator_list:
        dname = (_decorator_name(dec) or "").lower()
        if "tool" in dname or "mcp" in dname or dname in ("server.tool", "fastmcp.tool"):
            return True
    for a in fn.args.args:
        if a.arg.lower() in _PROMPTISH_PARAM_NAMES:
            return True
    for a in fn.args.kwonlyargs:
        if a.arg.lower() in _PROMPTISH_PARAM_NAMES:
            return True
    return False


def _caller_function_id(tree: ast.AST, call: ast.Call, rel: str, nid, seen_ids: set[str]) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                if child is call:
                    fid = nid(rel, "fn", node.name)
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                    return fid
    file_id = nid("file", rel)
    return file_id


def _is_excluded_test_path(rel: str) -> bool:
    rel_norm = rel.replace("\\", "/")
    return bool(_TEST_PATH_RE.search(rel_norm))
