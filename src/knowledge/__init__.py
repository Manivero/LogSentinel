"""Optional, fully local retrieval-augmented generation (RAG) layer.

Depends on `src.core`, `src.utils`, and `src.ollama` (embeddings go
through the existing `OllamaClient.embed`, never a new HTTP client).

Entirely optional: every entry point degrades gracefully when disabled
or unavailable, per `KnowledgeConfig.enabled` — nothing else in the
codebase requires this package to function. `src.analysis.ai_analyzer`
and `src.analysis.prompts` already treat `knowledge_context=None` as the
normal case.

- `base.py` — `KnowledgeSource` interface every loadable reference
  source implements.
- `sources/` — bundled MITRE ATT&CK, Sigma-style, and OWASP reference
  loaders, plus a loader for a user-supplied custom directory.
- `embeddings.py` — chunking + Ollama embedding calls.
- `vector_store.py` — local, persistent ChromaDB wrapper (telemetry
  explicitly disabled — see that module's docstring).
- `retriever.py` — `KnowledgeBase`, the package's public facade: builds
  the index from sources and answers "what's relevant to this query?"
"""
