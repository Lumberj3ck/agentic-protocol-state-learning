Normalization applied before comparing: {"UA_SUCCESS+GLOBAL_REQUEST": "UA_SUCCESS"} (raw outputs kept in the .json)

| # | status | sequence (divergence at the marked input) | outputs at divergence | reason | evidence |
|---|---|---|---|---|---|
| 1 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **SR_CONN** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 2 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN **SR_AUTH** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 3 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN **SR_CONN** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 4 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN **UA_PK_OK** | UNIMPL: openssh; NO_RESP: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 5 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN KEXINIT **NEWKEYS** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 6 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN KEXINIT KEX30 **KEX30** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 7 | reportable | KEXINIT KEX30 NEWKEYS **SR_CONN** | DISCONNECT: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 8 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **SR_CONN** | DISCONNECT: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 9 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **CH_OPEN** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 10 | reportable | KEXINIT KEX30 NEWKEYS **CH_OPEN** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 11 | agree | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN |  | all servers identical | `results/replay/B_only_replay.json` |
