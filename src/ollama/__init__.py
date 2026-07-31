"""Model-agnostic Ollama integration: client, health checks, model
selection, and streaming response handling.

Depends on `src.core` and `src.utils` only. Endpoint shapes are verified
against the official Ollama API reference
(https://github.com/ollama/ollama/blob/main/docs/api.md and
https://docs.ollama.com/api).
"""
