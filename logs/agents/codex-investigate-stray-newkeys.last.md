Created [CANDIDATE-002-libssh-stray-newkeys.md](findings/CANDIDATE-002-libssh-stray-newkeys.md) with exact outputs and tagged source references.

- **libssh:** enters a terminal session error before switching keys. The watched socket stayed open for 120 seconds; CPU remained negligible and other connections worked.
- **russh:** silently ignores stray NEWKEYS, retaining keys and normally advancing counters.

Included the diagnostic script and raw results. Severity assessed as informational / low, with deployment-impact qualifications.