"""What is allowed out of this computer, decided by an allowlist.

A blocklist of "strip command, strip args, strip paths" is one new hook kwarg away from leaking;
an allowlist is wrong only in the direction of sending too little. So the rule is: a field reaches
the sealed payload because it is named here, and everything Hermes hands a hook — the command text,
tool arguments, file paths, transcripts, error bodies — is dropped by not being named.
"""

from __future__ import annotations

from typing import Any, Dict

PREVIEW_LIMIT = 160
# The tunnel's limit, not the relay's. See :func:`detail_text`.
DETAIL_LIMIT = 400

# Identity, state, and the ids a deep link needs. Nothing a tool was pointed at.
ALLOWED = frozenset({
    "kind", "threadId", "agentName", "agentId", "turnId", "toolCallId", "requestId", "name",
    "outcome", "preview",
})


def redact(event: Dict[str, Any]) -> Dict[str, Any]:
    """The subset of ``event`` that may be sealed, with the preview truncated."""
    kept = {key: value for key, value in event.items() if key in ALLOWED and value is not None}
    preview = kept.get("preview")
    if isinstance(preview, str):
        kept["preview"] = preview_text(preview)
    return kept


def preview_text(text: str, *, mode: str = "sealed") -> str:
    """One line of reply text, or the content-free stand-in when previews are turned off."""
    if mode == "none":
        return "New activity"
    flattened = " ".join(str(text).split())
    if len(flattened) <= PREVIEW_LIMIT:
        return flattened
    return flattened[: PREVIEW_LIMIT - 1].rstrip() + "…"


def detail_text(text: str) -> str:
    """One bounded line of an approval's description, for the TUNNEL only.

    This is the one string that may name what an approval covers, and it exists because an approval
    card that cannot say anything about the ask is a card nobody can answer honestly. It is safe
    here and nowhere else: the host hands the transport a description it has already run through
    ``redact_sensitive_text(force=True)``, and the only reader is the dashboard route, which the
    phone reaches through its own SSH tunnel. It must never reach :func:`redact`, whose payloads
    cross a third-party relay — which is why "detail" is not in ``ALLOWED``.
    """
    flattened = " ".join(str(text).split())
    return flattened[:DETAIL_LIMIT]
