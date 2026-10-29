# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
* **AbuseIPDB auto-reporting** (`internal/abuseipdb`, optional): confirmed attackers are reported with the
  documented `POST /api/v2/report` call (categories 15 / 18 / 20 / 21 / 23 by evidence, comment with ATT&CK ids and a
  defanged dropper URL, no sensor address or personal data). One report per address per `HP_ABUSE_WINDOW` (24 h),
  state kept in `abuseipdb-state.json`, back-off on 429 / 5xx, reporting switches itself off on a rejected key.
  Password guessing (two or more login attempts) is reported as Brute-Force (18) but does not alert Telegram;
  `HP_ABUSE_REPORT_BRUTE=false` turns that off. A bare path (for example `GET /.env`)
  is never reported. New event field `abuse_reported`, counters `honeypot_abuseipdb_*`, a line in the weekly digest.
  `install.sh` asks for the key (hidden input, validated against the API), also via `--abuseipdb-key`,
  `ABUSEIPDB_API_KEY`, `--no-abuseipdb` and `--skip-abuseipdb-check`; `--yes` reuses a saved key. See
  [docs/ABUSEIPDB.md](docs/ABUSEIPDB.md).
* **Full-sensor simulation** (`TestFullSensorSimulation`, report in [docs/SIMULATION_REPORT.md](docs/SIMULATION_REPORT.md)):
  42 research-based scenarios over real sockets on all six ports and both profiles.
* **Camera / DVR web personas** (`internal/webcam`): Hikvision (host port 80), TVT (81) and
  Dahua (8080) with recognition of the Hikvision CVE-2021-36260 and CVE-2017-7921 patterns and
  the Dahua CVE-2021-33044 / CVE-2021-33045 login bypasses. New event field `signature`,
  shown in alerts and in the weekly digest. See [docs/WEB_PERSONAS.md](docs/WEB_PERSONAS.md).
* `HP_WEB_PORTS` and `HP_PORT_LABELS`; telemetry and alerts now report the public port
  (Telnet is `23`, not `2323`). `install.sh` upgrades an old default `HP_PORTS` automatically.
* **Weekly Telegram digest** (`internal/digest`): sessions, unique IPs, top ASNs and
  countries and most frequent shell commands for the last 7 days, rendered as
  monospace `<pre>` blocks. No file hashes are listed. Settings `HP_DIGEST_ENABLED`,
  `HP_DIGEST_DAY`, `HP_DIGEST_AT`, `HP_DIGEST_TOP`, `HP_DIGEST_ENRICH_MAX`; flags
  `-digest-preview` and `-digest-now`; counter `honeypot_digests_sent_total`.

* Hikvision **CVE-2025-34067** signature (`POST /bic/ssoService/v1/applyCT` with a fastjson
  `@type` plus a JNDI URL) with a JSON decoy reply; coverage table of what is and is not matched
  in [docs/WEB_PERSONAS.md](docs/WEB_PERSONAS.md).


* **Alert de-duplication rewritten**: the same attacker repeating the same attack is alerted once
  per `HP_ALERT_COOLDOWN` (default now `6h`, was `10m`); the same payload URL or file hash from
  *any* address is alerted once per `HP_ALERT_CAMPAIGN_COOLDOWN` (default `6h`). The memory is
  written to `<HP_LOG_DIR>/alert-state.json` (mode 600, `HP_ALERT_STATE=off` disables) so a
  restart or update no longer repeats alerts, and a failed Telegram delivery does not suppress
  the retry. Suppressed repeats are still stored in the JSONL and counted in the weekly digest.
* **NFS-mount droppers** (`mount ... host:/export dir; sh dir/script.sh`, used with the Hikvision
  CVE-2021-36260 exploit) are extracted as a new IOC type `nfs`, shown in alerts as
  `📂 NFS: host:/export → script.sh`, counted as Ingress Tool Transfer (T1105) and included in alert
  de-duplication. Nothing is mounted or fetched by the sensor.
* Events now carry the persona that actually answered a request (a vendor path on another vendor's port
  is answered by that vendor's persona), not just the persona configured for the port.

### Fixed
* PHP-CGI argument injection (`allow_url_include`, `auto_prepend_file`, `php://input`, `<?php shell_exec(...)`) is
  recognised on the strict camera ports, and `shell_exec(` / `passthru(` count as a shell command. Base64
  blobs that decode to a download or shell command (`base64_decode("...")`) are decoded before IOC
  extraction, so the hidden dropper URL is found, downloaded and hashed.
* The `Host:` header of a request is no longer scanned for indicators, so the sensor's own address
  no longer appears as an IOC in alerts.

### Changed
* Camera / DVR ports are strict: signatures need the exact documented pattern (Hikvision
  token `auth=YWRtaW46MTEK`, `PUT /SDK/webLanguage` with injection, Dahua `global.login` with
  `NetKeyboard` / `Loopback`), path-only heuristics are off there, and shell words in query
  parameters (`&cd=`, `&sh=`) no longer count as injection. Crawler traffic is logged with the new
  `persona` field but never alerted. Covered by table-driven tests and an end-to-end test.
* New front-page `README.md` (project name **BotBait**); the full design document moved to
  [`docs/TECHNICAL_REPORT.md`](docs/TECHNICAL_REPORT.md). Preview images in `docs/images/`.
* Source code no longer carries `//` comments (compiler directives such as `//go:embed` are kept).
* Alert layout: bold header (wraps cleanly on phones), action label inside the payload block, bold field labels, monospace IP / ISP-ASN / ATT&CK / SHA-256,
  reputation links as inline buttons (VirusTotal, AbuseIPDB, Check-Host), and
  only the SHA-256 of captured files is shown (no file names; safe for public channels).
* Default HTTP listener moved from 8080 to **7547** (TR-069/TR-064 CWMP);
  `HP_HOST_PORT_HTTP` is now `HP_HOST_PORT_TR069`.

## [1.0.0] - 2026-10-26

### Added
* Raw-TCP listeners with admission control, worker pools, graceful shutdown,
  Slowloris/idle/total deadlines, per-IP token-bucket rate limiting.
* HTTP (TR-064/TR-069 SOAP), ADB and Telnet emulation behind one protocol sniffer.
* **ADB file-transfer capture**: `adb push` (sync `SEND`/`DATA`/`DONE`) is
  streamed into a quota-bounded, content-addressed sample store, with
  `Incomplete` transfers kept as evidence.
* **Device "legend" profiles** (`android-tvbox`, `router-busybox`, custom JSON)
  with per-deployment identifier randomisation to resist fingerprinting.
* **Shell emulator** (never executes anything): pipes, redirections, `&&`/`||`,
  loops, `sh -c`, `base64 | sh`, copy-on-write virtual file system. Files an
  attacker writes are harvested, even if deleted afterwards.
* Shared Telnet persona (BusyBox router) on the same emulator.
* IOC extraction (with SOAP/XML blacklist), MITRE ATT&CK mapping
  (T1190, T1059.004, T1105, discovery), safe asynchronous HTTP payload
  downloader (SSRF-guarded, <=5 s, <=15 MiB, SHA-256 + metadata).
* ip-api.com ASN enrichment, Telegram alerts, JSONL event log, Prometheus metrics.
* Multi-stage Docker image (`scratch`, UID 10001), hardened `docker-compose.yml`,
  one-command `install.sh`.
* Offline analysis pipeline (SQLite loader, threat report, synthetic data).
* Uploaded files read back their real content from the sample store (`cat`,
  `md5sum`, `head -c` ... after `adb push`); device binaries read as ELF images
  for the profile's CPU (Mirai architecture probe); `dd`, `od`, `hexdump`, `xxd`,
  `strings`, `file`, `head/tail -c`; profile `exec_rules` and path-keyed
  `commands` for scripted "magic" behaviour; `-check-profile` / `-list-profiles`.
