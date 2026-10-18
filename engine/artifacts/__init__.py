"""
Model and binary artifact auditing.

The source-code pipeline (AST tracer + semantic LLM) cannot see inside compiled
executables, model weights, or Hugging Face model repositories. This package fills
that gap with deterministic inspectors whose output is both reported as findings
and handed to the semantic analyzer as evidence:

* ``gguf``          — GGUF header/metadata/tensor-table parser and anomaly checks
* ``safetensors``   — safetensors header validation
* ``pickle_scan``   — opcode-level pickle disassembly for code-execution imports
* ``chat_template`` — Jinja chat-template SSTI / hidden-instruction checks
* ``binary_triage`` — strings/entropy/capability triage for executables
* ``rea_bridge``    — REA (morluto/rea) reverse engineering of binaries and apps
* ``huggingface``   — Hugging Face model card + repository audit
"""
