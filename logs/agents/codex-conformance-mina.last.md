Created [the finding](findings/CANDIDATE-004-mina-sshd-service-request-after-auth.md) with replay outputs, tagged source references, RFC citations, and confidence limits.

All five sequences reproduced deterministically across four targets, three runs each.

MINA replaces the active connection service without closing its old channels. Their entries remain in the old map but become unavailable to active routing.

Verdict: acceptance alone is not explicitly prohibited; failing to answer the established channel’s `CHANNEL_CLOSE` conflicts with RFC 4254 §5.3.

No changes to `src/`, `tests/`, `docs/`, or `targets/`.