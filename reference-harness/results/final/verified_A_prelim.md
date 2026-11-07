Normalization applied before comparing: {"UA_SUCCESS+GLOBAL_REQUEST": "UA_SUCCESS"} (raw outputs kept in the .json)

| # | status | sequence (divergence at the marked input) | outputs at divergence | reason | evidence |
|---|---|---|---|---|---|
| 1 | reportable | **KEX30** | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 2 | reportable | **NEWKEYS** | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 3 | reportable | KEXINIT **NEWKEYS** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 4 | reportable | KEXINIT KEX30 **KEX30** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 5 | reportable | KEXINIT KEX30 NEWKEYS **UA_PK_OK** | UNIMPL: openssh; UA_SUCCESS: dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 6 | reportable | KEXINIT KEX30 NEWKEYS **KEXINIT** NEWKEYS | UNIMPL: openssh; KEXINIT: dropbear, gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 7 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **SR_AUTH** | SR_ACCEPT: openssh, dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 8 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **KEXINIT** NEWKEYS | UNIMPL: openssh; KEXINIT: dropbear, gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 9 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **SR_AUTH** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 10 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **UA_PK_OK** | UNIMPL: openssh; NO_RESP: dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 11 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **KEXINIT** KEX30 KEX30 | UNIMPL: openssh; KEXINIT: dropbear, gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 12 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT **NEWKEYS** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
| 13 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEX30 **KEX30** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/A_dropbear_vs_gossh_replay.json` |
