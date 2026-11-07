# Code review: v2 changes since `submission-1700`

Scope: `git diff submission-1700..78133fe` plus the uncommitted working tree as of 2026-11-07 16:30.
I traced each finding below through the code and the cited `results/` files.
I dropped anything I could not confirm.
No code, results or docs were changed by this review.

What I checked that holds up (not findings):
- v1 is untouched. Against the tag, every tracked change is an added file or an append to `report.md`, `JOURNAL.md`, `TASKS.md`, `PROMPT.md` or `.gitignore`. There are 0 deleted lines and no v1 code or `results/` file was modified.
- Every new SUT and mapper binds to 127.0.0.1 (`suts/b1/run.sh`, `harness/v2_sweep_one.sh`, `scripts_v2/a_start_mapper.sh`; the mappers use `--network host` with `-l/-s 127.0.0.1`). Every container is named `psm-*`.
- B1 images are pinned by base digest and package version or tarball sha256.
- The stream-A replay differential counts in `results/v2/A/harness_disagreements.md` match `results/v2/A/xreplay_nonstrict.json`: 120/120 KEXINIT-first pairs agree, 65 mismatches, 8 classes with the stated pair counts, 0 nondeterministic, no short runs.
- The catalogue hit-set claims in `journal/A.md` 16:24 match `results/v2/A/catalogue_results.json`.
- The "theirs wrong" Go claim (H5) matches `results/v2/A/xdiff_replay_gossh_nonstrict.json`: their model differs from their own live run, and both live runs agree.
- H3 (Dropbear) and H4 are supported by `results/v2/A/third_probe2.json`, which landed at 16:26.
- The B2 OpenSSH claims (D1-D8 identical from 7.5p1 to 10.0p1; D9 changes between 8.8p1 and 9.0p1) match `results/v2/B2/version_matrix.md`.
- `psm/xharness.py`: the initial-state split, the output maps and `ours_to_theirs` are correct for the cases exercised, and `tests/test_v2_xharness.py` covers them.

## Findings, most severe first

### 1. B2 "first EXT_INFO in Dropbear 2022.82" is false, and the Dropbear sweep has a hole where v1's versions should be. Weakens a claim.

- Where: `report.md` v2-B2 bullet 3 ("2022.82 is the first version that sends EXT_INFO"); `JOURNAL.md` 16:20; `results/v2/B2/version_matrix.md`; `psm/class_matrix.py:76-85`.
- What's wrong:
  - v1's own replay `results/final/final_check_dropbear2020.json` shows Dropbear 2020.81 sending `KEX31+NEWKEYS+EXT_INFO`, and it used the `legacy` profile too (README).
  - So EXT_INFO first appears at or before 2020.81, not at 2022.82.
  - The report says the sweep includes "v1's 2020.81, 2022.83, 2025.88", but the matrix has no 2020.81 or 2022.83 row.
  - The "(changed)" marks at 2022.82 exist only because the row before it is 2019.78.
  - That same 2019.78 → 2022.82 boundary is also where the mapper profile switches from `legacy` to `modern` (`harness/v2_sweep_list.txt`), so the KEX and host-key algorithms change at the same point as the version. Any difference at this boundary is confounded.
- Scenario: a reader concludes that Dropbear added RFC 8308 in 2022.82 and that all of 2017-2025 was compared. In fact two of the claimed versions are missing, and the one cited change point is an artifact of the gap.
- Fix:
  - Add the v1 2020.81 and 2022.83 replays to the matrix input. Rename their targets to `dropbear-2020.81` and `dropbear-2022.83`, because `psm/class_matrix.py:78` groups rows by `name.split("-")[0]`, and `dropbear2020` would never be compared with its neighbours.
  - Correct the text to "EXT_INFO first seen between 2019.78 and 2020.81".
  - Note that the profile switch coincides with that boundary.
- Related minor problem: the docstring advertises `--order`, but the option is not implemented. Row order is just the order of the files on the command line. That is why the 10.0p1 row (`openssh`) comes after the Dropbear rows and is never compared with 9.9p2. A future `openssh-10.x` file would also sort lexically before `7.5`.

### 2. B2 version pinning is not in the repo. Weakens a claim.

- Where: `report.md` v2-B2 bullet 1 cites `suts/sweep/*/Dockerfile` and `VERSION.md`; `harness/v2_sweep_one.sh:7,21-34`.
- What's wrong:
  - The script generates the Dockerfiles and VERSION.md files on the box.
  - `./gx` syncs only `results/` back, so they never reach the laptop.
  - Locally `suts/sweep/` is an empty directory, and `git ls-files suts/sweep` is empty.
  - The 18 files exist only on the shared box. I checked with `./gx ls suts/sweep`.
  - The base digest is looked up at run time from whatever `alpine:$AV` tag is present on the box, so it is recorded nowhere else.
- Scenario: the box is cleaned, or someone re-pulls `alpine:3.15`. The "pinned by digest" claim then cannot be checked or reproduced from the repo.
- Fix: write the generated Dockerfile and VERSION.md under `results/v2/B2/sweep/<impl>-<ver>/` as well, so they come back. Alternatively, rsync `suts/sweep/` back once and commit it.

### 3. H2 is labelled "setup difference", but by the doc's own definition ours is wrong. Weakens the stream-A headline.

- Where: `results/v2/A/harness_disagreements.md`, the "Verdict categories" line and the H2 section, plus the Part 2 table column "H2 hidden close".
- What's wrong:
  - The doc defines a setup/abstraction difference as one where both harnesses report correctly what the server did.
  - In H2, the server closes the TCP connection right after the first packet, in both message orders. `results/v2/A/third_probe.json` and `third_probe_openssh_ua.json` show `CLOSE` immediately, 3/3.
  - Our mapper reports `NO_RESP` for that step, meaning the connection is still alive, and only shows `NO_CONN` one step later.
  - Our model is therefore wrong about the state after step 1. It is a known abstraction limit, but it is still ours being wrong, not a difference in what was sent.
- Scenario: the answer to "how often is each harness wrong" puts 25 of the 65 replay mismatches and 11 of the 32 model classes in the neutral bucket. They are really known errors in our harness. The real tally of our errors is roughly double what the tables suggest: 15 classes (11 taint + 4 CH_MAX) become 26.
- Fix: reclassify H2 as "ours wrong (known abstraction: a close in the same step is hidden)". Alternatively, change the category definition and say explicitly that it excludes close timing.

### 4. The strict-KEX count is off by one, and the change hides a strict-only behaviour. Minor.

- Where: `results/v2/A/harness_disagreements.md`, "Strict KEX on": "the 65 mismatches above, plus 8 more".
- What's wrong:
  - `results/v2/A/xreplay_strict.json` has 64 auto-KEXINIT mismatches plus 8 unclassified, which is 72, not 73.
  - The missing one is Dropbear `KEX30 KEXINIT`. It agrees under strict (theirs `UNIMPL NO_CONN`) but is `UNIMPL NO_RESP` non-strict.
  - So strict mode changes Dropbear's reaction on a word whose first input is not KEXINIT. The text does not mention this.
- Fix: correct the count to 72 and list that pair.

### 5. The catalogue N/A note is applied only to our models. Minor.

- Where: `scripts_v2/verify_witnesses.py:45`.
- What's wrong:
  - The "not applicable" note for the STRICT-KEX-* patterns is set only when `kind == "ours"`.
  - Their non-strict models also hit those patterns (`openssh_nonstrict`, `dropbear_nonstrict` in `catalogue_results.json`). They get verdict CONFIRMED with no note.
- Scenario: counting the CONFIRMED rows in `catalogue_verified.json` includes strict-KEX "violations" on runs where strict KEX was never negotiated.
- Fix: mark N/A whenever the model was learned without strict KEX, for example `kind == "ours" or not strict`.

### 6. B1 uses a second, unchecked class-matrix script. Minor (latent).

- Where: `suts/b1/class_matrix.py:16-17`.
- What's wrong:
  - It takes the last output of each representative and does not check the prefix.
  - `psm/class_matrix.py` does check the prefix, and it flags libssh: in `results/v2/class_matrix_servers.md` every libssh cell is marked "prefix differs".
  - `results/v2/B1/class_matrix.md` shows the same libssh and russh cells with no warning. russh has the same EXT_INFO shift: `KEXINIT KEX31+NEWKEYS EXT_INFO ...`.
  - If a server closed earlier in the prefix, its NO_CONN would be recorded as the class behaviour.
  - No current cell is wrong because of this; I checked the full traces in the file.
  - The script has no tests.
- Fix: drop `suts/b1/class_matrix.py` and build the B1 table with `psm.class_matrix`, which is tested and prefix-aware.

### 7. The third client matches each harness's message order, not its message contents. Minor.

- Where: `scripts_v2/third_probe.py:26-44` and the "exactly either harness's message order" wording in `harness_disagreements.md`.
- What's wrong:
  - For the "ours-order" cases, the probe offers curve25519 and sends an ECDH KEX30 (32-byte X25519 key).
  - Our mapper offers and sends DH group14 (`alphabet_map.json`, KEX30).
  - The H1 verdict "`30, 20, 30` gives `31, 21`" therefore holds for the probe's KEX, not byte-for-byte for ours.
  - The packet types match, so the verdict is very likely unchanged.
- Fix: state "same message order, different KEX method", or offer `diffie-hellman-group14-sha256` in the probe for the ours-order cases.

### 8. russh dependencies are not pinned in the repo. Minor.

- Where: `suts/russh/Dockerfile:5`; `suts/russh/VERSION.md`.
- What's wrong:
  - `cargo build` runs without `--locked`, and the committed `Cargo.lock` does not cover the `rsa` feature.
  - The resolved lock exists only inside the image (`/Cargo.lock.resolved`).
- Scenario: a rebuild resolves newer transitive crates, such as `ssh-key` or `rsa`, and the russh row changes with no version change.
- Fix: copy the resolved lock out of the image, commit it, and build with `--locked`.

### 9. Duplicated vocabulary-mapping code in `tm_xreplay.py`. Minor.

- Where: `scripts_v2/tm_xreplay.py:17-36`.
- What's wrong:
  - It re-implements `psm.xharness.map_theirs_output` and `map_ours_output` instead of importing them.
  - The copies already differ: `map_ours` drops only EXT_INFO, while `psm.xharness` also drops IGNORE and DEBUG.
  - This has no effect today: none of the 192 `ours_raw` rows contain IGNORE or DEBUG.
  - But the replay differential and the model differential can drift apart silently, and this copy is untested.
- Fix: import the mappers from `psm.xharness`.

## Watch items (risks, not confirmed defects)

- `harness/v2_sweep_learn.sh` starts all 18 B2 learners at once, alongside the A and B1 jobs.
  The mapper's Dropbear timing profile waits only 0.3 s (`global_to`), so CPU contention could turn late replies into NO_RESP or nondeterminism in the B2 models.
  Before using those models, check the nondeterminism stats and re-replay their divergence points with no other load.
- The B1 candidates on libssh and wolfSSH (pre-auth SR_CONN accepted, unsolicited SERVICE_ACCEPT) go through our own `server.c` callback code.
  For example, `suts/libssh/server.c` installs no service-request callback.
  The skeptic should establish whether each behaviour belongs to the library or to our minimal server before it is attributed to the implementation.

## Verdict

The v2 code leaves v1 intact, binds everything to 127.0.0.1, and its stream-A numbers mostly reproduce from the cited results; I found no bug that flips a reported comparison.
Two B2 claims in report.md are not supported by the repo: the Dropbear EXT_INFO change point (contradicted by v1's 2020.81 replay, with two claimed versions missing from the matrix) and the sweep pinning (Dockerfiles live only on the box).
Stream A's verdict taxonomy understates our own harness's errors: H2 is "ours wrong", not "setup". Fix that before the harness-trust answer is written.

Reviewed up to commit `78133fe` (plus the working tree at about 16:30 on 2026-11-07); the next review should start from `78133fe`.

## Added after 16:30

No further findings beyond the above.
The review stopped at the lead session's request.
The lead reports findings 1-4 applied in 94fc169; this review has not re-checked that commit.
