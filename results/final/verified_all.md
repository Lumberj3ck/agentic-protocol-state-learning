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
| 14 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **SR_CONN** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 15 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN **SR_AUTH** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 16 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN **SR_CONN** | UNIMPL: openssh; SR_ACCEPT: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 17 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN **UA_PK_OK** | UNIMPL: openssh; NO_RESP: dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 18 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN KEXINIT **NEWKEYS** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 19 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN KEXINIT KEX30 **KEX30** | UNIMPL: openssh, dropbear; NO_CONN: gossh |  | `results/replay/B_only_replay.json` |
| 20 | reportable | KEXINIT KEX30 NEWKEYS **SR_CONN** | DISCONNECT: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 21 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **SR_CONN** | DISCONNECT: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 22 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **CH_OPEN** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 23 | reportable | KEXINIT KEX30 NEWKEYS **CH_OPEN** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/B_only_replay.json` |
| 24 | agree | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN |  | all servers identical | `results/replay/B_only_replay.json` |
| 25 | reportable | **SR_AUTH** | KEXINIT+UNIMPL: openssh; KEXINIT: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 26 | reportable | **KEX30** KEXINIT | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 27 | reportable | **KEX30** SR_AUTH | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 28 | reportable | KEXINIT **KEXINIT** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 29 | reportable | KEXINIT **SR_AUTH** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 30 | reportable | **KEX30** KEX30 KEXINIT | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 31 | reportable | **KEX30** KEX30 SR_AUTH | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 32 | reportable | KEXINIT KEX30 **KEXINIT** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 33 | reportable | KEXINIT KEX30 **SR_AUTH** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 34 | reportable | **KEX30** KEX30 NEWKEYS KEX30 | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 35 | reportable | **KEX30** KEX30 NEWKEYS KEXINIT | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 36 | reportable | **KEX30** KEX30 NEWKEYS NEWKEYS | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 37 | reportable | **KEX30** KEX30 NEWKEYS UA_PK_OK | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 38 | reportable | KEXINIT KEX30 NEWKEYS **KEX30** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 39 | reportable | KEXINIT KEX30 NEWKEYS **KEXINIT** | UNIMPL: openssh; KEXINIT: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 40 | reportable | KEXINIT KEX30 NEWKEYS **NEWKEYS** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 41 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH KEX30 | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 42 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH KEXINIT | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 43 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH NEWKEYS | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 44 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **KEX30** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 45 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **KEXINIT** | UNIMPL: openssh; KEXINIT: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 46 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH **NEWKEYS** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 47 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK KEX30 | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 48 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK NEWKEYS | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 49 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK SR_AUTH | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 50 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK UA_PK_OK | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 51 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **KEX30** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 52 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK **NEWKEYS** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 53 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEXINIT | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 54 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT SR_AUTH | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 55 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT UA_PK_OK | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 56 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT **KEXINIT** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 57 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT **SR_AUTH** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 58 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT **UA_PK_OK** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 59 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEX30 KEXINIT | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 60 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEX30 SR_AUTH | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 61 | reportable | **KEX30** KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEX30 UA_PK_OK | KEXINIT+UNIMPL: openssh, dropbear; KEXINIT: gossh |  | `results/replay/A_threeway_replay.json` |
| 62 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEX30 **KEXINIT** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 63 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEX30 **SR_AUTH** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
| 64 | reportable | KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT KEX30 **UA_PK_OK** | UNIMPL: openssh; NO_CONN: dropbear, gossh |  | `results/replay/A_threeway_replay.json` |
