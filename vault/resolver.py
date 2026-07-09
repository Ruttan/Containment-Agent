"""
Secret resolution — the actual enforcement mechanism.

This is a whitelist, not a heuristic: only the specific config paths listed
below are ever treated as secrets, and each one is trusted to hold a
*reference name*, never a literal value. When resolve_secrets() runs, it
looks up each reference name through the active backend and replaces it in
place with the real secret.

Why a whitelist instead of scanning for "things that look like secrets":
it's unambiguous, it's easy to audit (this file *is* the list of what's
sensitive in this project), and it means there's no code path anywhere that
accepts a plaintext credential from config.yaml — if someone pastes a real
API key into one of these fields instead of a reference name, the lookup
will simply fail (the backend won't have an entry with that literal key as
its name), which is the correct behavior: it forces the secret into the
vault/database instead of silently accepting it.

If you add a new connector/notifier/integration with its own credential,
add its config path here too.
"""

import logging

# Paths are tuples of nested dict keys. Each one, if present and non-empty
# in config.yaml, is treated as a reference name to resolve.
SECRET_FIELD_PATHS = [
    ("anthropic_api_key",),
    ("platforms", "crowdstrike", "client_secret"),
    ("platforms", "tanium", "api_token"),
    ("platforms", "defender", "client_secret"),
    ("platforms", "generic", "api_key"),
    ("notifications", "slack", "webhook_url"),
    ("notifications", "email", "password"),
    ("integrations", "siem", "splunk_hec", "token"),
]


def _get_nested(d: dict, path: tuple):
    for key in path:
        if not isinstance(d, dict) or key not in d:
            return None
        d = d[key]
    return d


def _set_nested(d: dict, path: tuple, value):
    for key in path[:-1]:
        d = d.setdefault(key, {})
    d[path[-1]] = value


def resolve_secrets(config: dict, provider) -> dict:
    """
    Mutates and returns `config` with every whitelisted secret field
    resolved from its reference name to its real value via `provider`.
    Fields that are absent or empty are left alone (that platform/feature
    just isn't configured).
    """
    for path in SECRET_FIELD_PATHS:
        ref_name = _get_nested(config, path)
        if not ref_name:
            continue
        real_value = provider.get(ref_name)
        _set_nested(config, path, real_value)
        logging.info(f"Resolved secret for {'.'.join(path)} (ref: '{ref_name}')")

    # generic_webhook can have arbitrary custom headers (e.g. an API key in
    # an Authorization header) — resolve every header value too.
    headers = _get_nested(config, ("integrations", "siem", "generic_webhook", "headers"))
    if isinstance(headers, dict):
        for header_name, ref_name in list(headers.items()):
            if ref_name:
                headers[header_name] = provider.get(ref_name)
                logging.info(f"Resolved secret for generic_webhook header '{header_name}'")

    return config
