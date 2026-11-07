Wrote [the finding](findings/CANDIDATE-003-wolfssh-non-kex-during-rekey.md) with all nine replay outputs, packet traces, and source references.

All sequences were deterministic over three runs. Both wolfSSH rekey sequences confirm an RFC 4253 §7.1 violation. Authentication before SERVICE_REQUEST is confirmed, but no explicit RFC MUST/SHOULD rejection requirement was established.

No files in src/, tests/, docs/, or targets/ were edited.