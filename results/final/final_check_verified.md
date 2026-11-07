Normalization applied before comparing: {"UA_SUCCESS+GLOBAL_REQUEST": "UA_SUCCESS"} (raw outputs kept in the .json)

| # | status | sequence (divergence at the marked input) | outputs at divergence | reason | evidence |
|---|---|---|---|---|---|
| 1 | agree | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN |  | all servers identical | `results/final/final_check_replay.json` |
| 2 | reportable | KEXINIT KEX30 NEWKEYS **UA_PK_OK** | UNIMPL: openssh; UA_SUCCESS: dropbear; NO_CONN: gossh |  | `results/final/final_check_replay.json` |
| 3 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **CH_OPEN** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/final/final_check_replay.json` |
| 4 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **KEXINIT** | UNIMPL: openssh; KEXINIT: dropbear, gossh |  | `results/final/final_check_replay.json` |
| 5 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **UA_PK_OK** | UNIMPL: openssh; NO_RESP: dropbear; NO_CONN: gossh |  | `results/final/final_check_replay.json` |
| 6 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **SR_AUTH** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/final/final_check_replay.json` |
| 7 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **SR_CONN** | DISCONNECT: openssh; NO_CONN: dropbear, gossh |  | `results/final/final_check_replay.json` |
| 8 | reportable | KEXINIT KEX30 **KEX30** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/final/final_check_replay.json` |
| 9 | reportable | **KEX30** | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/final/final_check_replay.json` |
| 10 | reportable | KEXINIT **KEXINIT** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/final/final_check_replay.json` |
| 11 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT **SR_AUTH** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/final/final_check_replay.json` |
