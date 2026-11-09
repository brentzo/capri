#!/usr/bin/env python3
"""The provider catalog Capri owns (HC-MODEL-01).

The model-plane gateway (Bifrost) can route to many LLM providers, but its own
supported-provider list lives behind an authenticated control-plane API whose labels
churn between versions. So Capri keeps its own catalog: the providers a self-hoster can
wire up with a single API key, each with a stable Bifrost identifier, the env var its
key lives in, and a few suggested models. This is the one place to edit to add or update
a provider; it is what the setup surface offers the user and what the gateway config is
generated from, so the operator/verifier pairing is a choice, never a hardcoded pair.

Scope is the providers Bifrost takes with a single API key (reflecting its current
direct-provider support, not a narrow shortlist). Multi-field providers (Bedrock,
Vertex, Azure, Databricks) and self-hosted ones (Ollama, vLLM, SGL, which need a URL)
need extra fields and are a separate path; add them here with those fields when the
setup surface grows to collect them. Identifiers are Bifrost's own; a route is
`<provider>/<model>`. Model lists are suggestions, recommended first; a user may type
any model the provider serves, and providers whose model names churn are left open.
"""

# Bifrost provider id -> catalog entry. `models` are suggestions (recommended first);
# an empty list means "type the model you want". Keep identifiers and key_env exact.
CATALOG = {
    "openai":      {"label": "OpenAI",        "key_env": "OPENAI_API_KEY",
                    "models": ["gpt-4o-mini", "gpt-4o"]},
    "anthropic":   {"label": "Anthropic",     "key_env": "ANTHROPIC_API_KEY",
                    "models": ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"]},
    "gemini":      {"label": "Google Gemini", "key_env": "GEMINI_API_KEY",
                    "models": ["gemini-2.0-flash", "gemini-1.5-pro"]},
    "deepseek":    {"label": "DeepSeek",      "key_env": "DEEPSEEK_API_KEY",
                    "models": ["deepseek-chat", "deepseek-reasoner"]},
    "mistral":     {"label": "Mistral",       "key_env": "MISTRAL_API_KEY",
                    "models": ["mistral-large-latest", "mistral-small-latest"]},
    "cohere":      {"label": "Cohere",        "key_env": "COHERE_API_KEY",
                    "models": ["command-r-plus", "command-r"]},
    "groq":        {"label": "Groq",          "key_env": "GROQ_API_KEY",
                    "models": ["llama-3.3-70b-versatile"]},
    "cerebras":    {"label": "Cerebras",      "key_env": "CEREBRAS_API_KEY",
                    "models": ["llama-3.3-70b"]},
    "xai":         {"label": "xAI (Grok)",    "key_env": "XAI_API_KEY",
                    "models": ["grok-2-latest"]},
    "perplexity":  {"label": "Perplexity",    "key_env": "PERPLEXITY_API_KEY",
                    "models": ["sonar", "sonar-pro"]},
    "openrouter":  {"label": "OpenRouter",    "key_env": "OPENROUTER_API_KEY",
                    "models": []},
    "nebius":      {"label": "Nebius",        "key_env": "NEBIUS_API_KEY",
                    "models": []},
    "huggingface": {"label": "Hugging Face",  "key_env": "HF_API_KEY",
                    "models": []},
    "replicate":   {"label": "Replicate",     "key_env": "REPLICATE_API_KEY",
                    "models": []},
}


def providers():
    """Catalog provider ids, in catalog (display) order."""
    return list(CATALOG)


def label(provider):
    return CATALOG[provider]["label"]


def key_env(provider):
    """The env var the provider's API key lives in (e.g. 'OPENAI_API_KEY')."""
    return CATALOG[provider]["key_env"]


def models(provider):
    """Suggested models for a provider, recommended first (may be empty; a user may
    always type a model the provider serves)."""
    return list(CATALOG[provider]["models"])


def default_model(provider):
    """The recommended model for a provider (the first suggestion), or None if the
    catalog leaves the model open for this provider."""
    ms = CATALOG[provider]["models"]
    return ms[0] if ms else None


def has_provider(provider):
    return provider in CATALOG


def route(provider, model):
    """The Bifrost model route for a provider/model pick (`<provider>/<model>`)."""
    return f"{provider}/{model}"


def entries():
    """The catalog as a list of {id, label, key_env, models} for a UI to render."""
    return [{"id": p, "label": e["label"], "key_env": e["key_env"],
             "models": list(e["models"])} for p, e in CATALOG.items()]


def validate_pairing(operator_provider, verifier_provider):
    """The invariant the catalog enforces for a pairing: operator and verifier must be
    known providers and must differ, so the finder never verifies on its own model
    (HC-MODEL-01 §4). Returns None if the pairing is allowed, else a human reason."""
    for role, p in (("operator", operator_provider), ("verifier", verifier_provider)):
        if not has_provider(p):
            return f"unknown {role} provider {p!r}"
    if operator_provider == verifier_provider:
        return "operator and verifier must be on different providers"
    return None
