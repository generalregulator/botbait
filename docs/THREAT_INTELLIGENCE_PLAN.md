# Threat Intelligence Data-Collection and Analysis Plan

Companion document to the honeypot. It defines **what to log, how to collect
it, which metrics to compute and how to turn them into a report** you can put
in a portfolio. Numbers in this repository's sample outputs are synthetic; your
report must only contain data measured by your own deployment.

---

## 1. Objective and scope

Characterise IoT-targeted attack activity observed by one internet-facing
sensor during a fixed collection window, answering the research questions of
TECHNICAL_REPORT.md (RQ1-RQ5), and produce a reproducible report (notebook + figures).

**Out of scope:** attributing attacks to people or organisations, measuring
the whole internet, and any interaction with attacker infrastructure beyond
the bounded payload fetch performed by the sensor.

## 2. Research questions, hypotheses and metrics

| RQ | Question | Hypothesis to test | Primary metrics |
|---|---|---|---|
| RQ1 | Where does it come from? | A few ASNs (consumer ISPs, hosting providers) account for most sessions, but *unique IPs per ASN* ranks them differently from *sessions per ASN* | M-O1..M-O4 |
| RQ2 | What is targeted? | Most sessions are scans; a minority carry an exploit; Telnet is dominated by brute force, HTTP by known router CVE paths | M-T1..M-T4, M-B1..M-B4 |
| RQ3 | What is installed and how is it distributed? | Few distinct payload hosts serve many source IPs (centralised distribution); samples are mostly architecture-suffixed ELF droppers | M-P1..M-P6 |
| RQ4 | How long do links live? | A large share of payload links are already dead on first fetch | M-P2, M-P7 |
| RQ5 | Which credentials are tried? | A small default-credential dictionary explains most attempts | M-C1..M-C3 |
| RQ6 | **How do bots deliver malware to exposed ADB?** | A large share of ADB droppers use `adb push` or shell-written files (no URL at all), so a URL-only sensor under-counts them; delivery channels differ by actor | M-F1..M-F5 |
| RQ7 | What do bots do after getting a shell? | A small, stable command vocabulary (reconnaissance -> drop -> chmod -> execute -> clean up) explains most sessions; Mirai-class Telnet bots probe BusyBox applets first | M-X1..M-X3 |

## 3. Collection protocol

1. **Fix the configuration** and record it: git commit, `.env` with the token removed, image digest, ports, rate-limit and timeout values. Do not change it mid-study; if you must, start a new "epoch" and record the change time.
2. **Deployment record** (one paragraph in the report): provider and region, OS, public IP type (IPv4/IPv6, fresh or previously used), exposed ports, start timestamp (UTC).
3. **Duration:** at least 14 days, ideally 28-30, so that weekday/weekend and daily cycles are both observed. Discard or flag the first hour (warm-up: caches, first scans).
4. **Daily checks** (5 minutes): container healthy, disk usage of `data/` and `captured_payloads/`, `events_dropped_total == 0`, number of JSONL lines grew.
5. **Sensor-health counters** are not in the JSONL (they describe traffic that was *not* processed). Scrape `/metrics` every 5 minutes into a CSV (publish it on the host loopback as described in TECHNICAL_REPORT.md) so that rate-limited and dropped connections can be reported:
   ```bash
   # crontab: */5 * * * *
   (date -u +%FT%TZ; curl -s http://127.0.0.1:9100/metrics | tr '\n' ' '; echo) >> ~/hp-metrics.log
   ```
6. **Backups:** copy `data/*.jsonl` daily to storage off the sensor (JSONL only; payloads stay in quarantine). Record a SHA256 of each day's file.
7. **End of study:** stop the container (graceful shutdown flushes the queue), archive `data/`, record the final counters, compute checksums, freeze the analysis commit.

## 4. Data model

### 4.1 Raw log: JSONL (one object per session)

| Field | Type | Notes |
|---|---|---|
| `id`, `timestamp` | string | random 64-bit ID; UTC RFC 3339 |
| `src_ip`, `src_port`, `dst_port` | string / int | TCP peer (handshake completed, so not spoofable) |
| `protocol`, `action` | string | `HTTP` / `ADB` / `TELNET` / `RAW`; e.g. `HTTP POST`, `ADB shell`, `Telnet login` |
| `http_method`, `http_path`, `user_agent` | string | first request of the connection |
| `payload` | string | sanitised session text, truncated (`HP_STORE_PAYLOAD_MAX`) |
| `bytes_received`, `truncated`, `session_duration_ms` | int / bool / int | |
| `commands[]`, `credentials[]` | arrays | shell commands (ADB `shell:`, interactive input, Telnet); `{username,password}` |
| `dropped[]` | array | files left on the emulated device: `{path,via[adb-sync-push\|shell-write],mode,status,success,incomplete,executable,sha256,filename,file_type,size,timestamp}`. The bytes are in `captured_payloads/<sha256>.bin`; the `.json` sidecar lists every sighting. |
| `iocs.{urls,download_urls,ips,domains}` | arrays | after FP filtering |
| `mitre[]` | array | `{id,name}` |
| `downloads[]` | array | `{url,status,success,cached,sha256,filename,file_type,content_type,size,duration_ms}` |
| `geo` | object | `{country,country_code,isp,asn,as_name,resolved}` (only for events with indicators; see 8) |
| `alert_sent` | bool | |

### 4.2 Analysis database: SQLite

`analysis/load_events.py` builds a normalised database (idempotent, re-runnable):

```
events(id PK, ts, src_ip, src_port, dst_port, protocol, action, http_method, http_path, user_agent,
       bytes_received, truncated, session_ms, country, country_code, isp, asn, as_name, geo_resolved,
       alert_sent, n_commands, payload)
event_techniques(event_id, technique_id, technique_name)
event_iocs(event_id, kind[url|download_url|ip|domain], value)
downloads(event_id, url, status, success, cached, sha256, file_type, content_type, size, duration_ms)
credentials(event_id, username, password)
commands(event_id, seq, command)
dropped_files(event_id, seq, path, via, mode, status, success, incomplete, executable, sha256, file_type, size)
-- recommended extra table, filled during malware triage (section 6):
sample_labels(sha256, source, label, confidence, labelled_at)
```

## 5. Metric catalogue

IDs are referenced from the RQ table. "Chart" names match the figures written by `analysis/threat_report.py` where one exists.

### Volume and time
| ID | Metric | Definition | Chart |
|---|---|---|---|
| M-V1 | Sessions per day by protocol | `COUNT(*) GROUP BY date, protocol` | `01_daily_by_protocol` |
| M-V2 | Unique source IPs per day | `COUNT(DISTINCT src_ip)` | line |
| M-V3 | Hour x weekday intensity | sessions by `dow, hour` (UTC) | `06_hour_weekday_heatmap` |
| M-V4 | New vs returning IPs | first-seen date of each IP | stacked bar |
| M-V5 | Time to first exploit | first event with any technique minus deployment start | single number |

### Origin
| ID | Metric | Definition | Chart |
|---|---|---|---|
| M-O1 | Sessions per ASN (top 15) | `GROUP BY asn` | `02_top_asn` |
| M-O2 | **Unique IPs per ASN** | `COUNT(DISTINCT src_ip) GROUP BY asn` | `02_top_asn` |
| M-O3 | Country distribution | `GROUP BY country` | `03_top_countries` |
| M-O4 | Concentration | cumulative share of sessions of the top-k ASNs (Pareto) | line |

### Targeting and behaviour
| ID | Metric | Definition | Chart |
|---|---|---|---|
| M-T1 | Port/protocol mix | `GROUP BY dst_port, protocol` | `04_service_mix` |
| M-T2 | Scan vs exploit ratio | sessions with no ATT&CK technique / with >= 1 | stacked bar |
| M-T3 | Top HTTP paths and User-Agents | `GROUP BY http_path`, `user_agent` | bar |
| M-T4 | Session duration and bytes | percentiles of `session_ms`, `bytes_received` by protocol | box plot |
| M-B1 | ATT&CK technique frequency | distinct events per technique | `05_mitre_techniques` |
| M-B2 | Technique combinations (mini kill chain) | e.g. `T1059.004 + T1105 + T1190` | table |
| M-B3 | Command vocabulary | most frequent first tokens in `commands` | bar |
| M-B4 | Mining indicators | events with T1496 | count |

### Credentials
| ID | Metric | Definition | Chart |
|---|---|---|---|
| M-C1 | Top usernames / passwords | counts | `07_credentials` |
| M-C2 | Top pairs | `username/password` | table |
| M-C3 | Dictionary coverage | share of attempts explained by the top-k pairs | line |

### Payloads, malware and infrastructure
| ID | Metric | Definition | Chart |
|---|---|---|---|
| M-P1 | Payload URLs seen / unique | `COUNT(*)`, `COUNT(DISTINCT url)` | number |
| M-P2 | **Download outcome distribution** | share of `status` (dead link, HTTP error, blocked, ok) | `08_download_status` |
| M-P3 | Unique samples | `COUNT(DISTINCT sha256)` | number |
| M-P4 | File types and sizes | `file_type`, size histogram | bar / histogram |
| M-P5 | **Malware family distribution** | label per unique SHA256 (section 6) | `09_families` |
| M-P6 | Payload infrastructure reuse | distinct source IPs per payload URL / host; distinct URLs per host | table |
| M-P7 | Link lifetime | per URL: first seen, last seen, success ratio over time | survival-style plot |
| M-P8 | Sample polymorphism | distinct SHA256 per URL path / host | table |

### Files left on the device and shell behaviour
| ID | Metric | Definition | Chart |
|---|---|---|---|
| M-F1 | Files dropped / unique samples | `COUNT(*)`, `COUNT(DISTINCT sha256)` over `dropped_files` where `success = 1` | number |
| M-F2 | **Delivery channel mix** | share of `via` (`adb-sync-push`, `shell-write`) next to `downloads` (HTTP) | `10_dropped_files` |
| M-F3 | Dropped file types and sizes | `file_type`, `size`; share `executable = 1` | bar / histogram |
| M-F4 | Drop paths | most common target directories (`/data/local/tmp`, `/tmp`, ...) | table |
| M-F5 | **Cross-channel overlap** | SHA256 seen both via HTTP and via push (same family, different delivery) | table |
| M-F6 | Capture completeness | share of drops with `status` != `Saved` (quota, size limit, per-session cap), share `incomplete = 1` | number |
| M-X1 | Command vocabulary | most frequent first tokens in `commands`, by protocol | `11_command_vocabulary` |
| M-X2 | Kill-chain order | position of recon / drop / `chmod` / execute / cleanup commands within a session | table |
| M-X3 | Reconnaissance fingerprints | which discovery commands bots issue first (`cat /proc/cpuinfo`, `busybox <X>`, `getprop ro.product.model`) | table |

### Sensor health and alerting (from the `/metrics` CSV)
| ID | Metric | Source |
|---|---|---|
| M-S1 | Connections accepted / rate-limited / per-IP-limited / queue-dropped | counters |
| M-S2 | Events dropped, session panics | counters (both must be 0) |
| M-S3 | Alerts sent / deduplicated / rate-limited / errors | counters |
| M-S4 | Files captured / not captured | `honeypot_files_captured_total`, `honeypot_files_not_captured_total` (the second must stay near 0; otherwise raise the quota) |

## 6. Malware family classification workflow

Treat labels as hypotheses with provenance, not facts. Record each label in
`sample_labels(sha256, source, label, confidence, labelled_at)`.

| Stage | Method | Output | Confidence |
|---|---|---|---|
| 0 | De-duplicate by SHA256 (already content-addressed) | unique sample set | - |
| 1 | Static triage inside an isolated VM: magic bytes, architecture (`file`), size, entropy, packer hints, `strings` (C2 addresses, user-agent strings, process names) | file type, strings | - |
| 2 | **Heuristics from names and strings** (implemented in `threat_report.py`: `mirai`, `mozi`, `okiru`, ..., arch-suffix, miner names) | weak family hint | low |
| 3 | **Hash lookup** in a multi-engine service (e.g. VirusTotal file report by SHA256, metadata only; do not upload samples that could contain private data) | detection ratio, vendor family names, suggested label | medium-high |
| 4 | Optional YARA rules (community botnet/miner rule sets) | rule hits | medium-high |
| 5 | Optional behavioural sandbox (isolated, network-controlled) | observed C2, persistence | high |

Report the **agreement** between stages (e.g. share of samples whose heuristic
label matches the majority vendor label) — it is a useful result in itself and
quantifies how misleading file names are.

## 7. Analysis plan and report figures

1. Load and validate: row counts per day, timestamp range, null rates, duplicates (`id` unique).
2. Describe: overview table (events, unique IPs, % exploit sessions, samples captured).
3. For each RQ produce 1-2 figures and one table with a short interpretation (what, so-what, caveat).
4. Two **case studies**: pick one payload URL/host with many distinct sources and one distinctive exploit path; reconstruct the timeline (first seen, spread across ASNs, payload hash variants, link death).
5. Cross-check a sample of classified events manually (read 30-50 raw payloads) to estimate the false-positive rate of the ATT&CK rules; report it.
6. Sensitivity checks: results with and without the first 24 h; with `rate_limited` counters added to the volume estimate.

Example queries:

```sql
-- Unique IPs vs sessions per ASN (M-O1/M-O2)
SELECT asn, isp, COUNT(*) AS sessions, COUNT(DISTINCT src_ip) AS ips
FROM events WHERE asn IS NOT NULL GROUP BY asn, isp ORDER BY sessions DESC LIMIT 15;

-- Payload hosts serving many sources (M-P6)
SELECT substr(d.url, instr(d.url,'//')+2, instr(substr(d.url, instr(d.url,'//')+2),'/')-1) AS host,
       COUNT(DISTINCT e.src_ip) AS sources, COUNT(DISTINCT d.sha256) AS samples
FROM downloads d JOIN events e ON e.id = d.event_id GROUP BY host ORDER BY sources DESC LIMIT 10;

-- Dead-link ratio per day (M-P7)
SELECT date(e.ts) AS day, AVG(d.success) AS success_ratio, COUNT(*) AS attempts
FROM downloads d JOIN events e ON e.id = d.event_id WHERE d.cached = 0 GROUP BY day;

-- Delivery channels (M-F2): HTTP downloads vs pushed / shell-written files
SELECT 'http-download' AS via, COUNT(*) AS n, COUNT(DISTINCT sha256) AS samples FROM downloads WHERE success = 1
UNION ALL
SELECT via, COUNT(*), COUNT(DISTINCT sha256) FROM dropped_files WHERE success = 1 GROUP BY via;

-- Same sample, two delivery channels (M-F5)
SELECT d.sha256, COUNT(DISTINCT e.src_ip) AS sources
FROM dropped_files d JOIN downloads w ON w.sha256 = d.sha256 JOIN events e ON e.id = d.event_id
WHERE d.sha256 IS NOT NULL GROUP BY d.sha256 ORDER BY sources DESC;

-- Time to first exploit (M-V5)
SELECT (julianday(MIN(e.ts)) - julianday((SELECT MIN(ts) FROM events))) * 24 AS hours
FROM events e JOIN event_techniques t ON t.event_id = e.id;
```

## 8. Threats to validity (put these in the report)

| Bias / error | Effect | How to mitigate or report |
|---|---|---|
| **Single sensor, single IP, single network** | Results describe this vantage point, not "the Internet" | State it; if possible deploy a second sensor in another provider/region and compare |
| **Honeypot fingerprinting** | Sophisticated actors may avoid it; data over-represents automated, non-evasive activity | Say so explicitly; do not generalise to targeted attacks. Record the device profile name/hash and `HP_TELNET_PROFILE` in the deployment record |
| **Persona choice** (Android box on ADB, BusyBox router on Telnet, or one device) | The persona may influence *which* bots continue past recon (plausibly Mirai variants on BusyBox, ADB miners on Android; to be tested, not assumed); the dataset is conditional on it | State the persona; a second sensor with the other persona is the cleanest control |
| **Always-acknowledged pushes, pretended downloads, emulated shell** | Bots that verify the upload or depend on real command output may abort early; their later behaviour is unobserved | Report session-length distributions; compare with a medium-interaction deployment if possible |
| **Capture limits** (15 MiB per file, storage quota, 8 files per session) | Large or numerous files are partially stored or missing | Report M-F6; keep `Incomplete` samples in the analysis |
| **Connection rate limiting** | Heavy sources are under-counted in sessions | Report the `rate_limited` / `per_ip_limited` counters; prefer *unique IPs* for breadth claims |
| **Geolocation/ASN accuracy** (ip-api free tier) and enrichment only for events with indicators | Country errors; ASN missing for plain scans | Validate a sample against a second source (RIR/WHOIS or an offline database); enrich all unique IPs offline in the notebook if needed |
| **NAT / CGNAT / shared IPs** | One IP may be many devices, many IPs one device | Interpret "unique IPs" as addresses, not hosts |
| **Dead payload links** | Survivorship bias: captured samples are the *live* subset | Report M-P2 and keep dead URLs in infrastructure analysis |
| **Time zone and short windows** | Daily patterns confounded by UTC and by a single week | Use >= 2 weeks and show UTC explicitly |
| **Rule-based ATT&CK labels** | False positives/negatives | Manual review sample (section 7, step 5) |
| **Heuristic family labels** | Names lie | Use stages 3-4 and report agreement |

## 9. Portfolio report outline

1. **Abstract** (150 words): sensor, window, headline findings with numbers.
2. **Background and research questions.**
3. **Sensor design**: architecture diagram, security controls (threat model summary), why low-interaction.
4. **Method**: deployment record, collection protocol, data model, ethics statement.
5. **Results** (one subsection per RQ): 6-8 figures with captions and interpretation.
6. **Case studies** (two).
7. **Discussion**: what defenders can do (e.g. blocklists, disabling ADB/TR-069 exposure, default-credential hygiene) and what the data cannot say.
8. **Limitations** (section 8) and **future work**.
9. **Appendix**: schema, ATT&CK rule table, configuration, reproducibility checklist.

Suggested timeline: day 0 deploy and verify; days 1-3 baseline checks; days 3-21 collection (analysis scripts developed on the first days' data); days 22-26 analysis and case studies; days 27-30 writing and review.

## 10. Reproducibility checklist

- [ ] Git commit hash of the honeypot and of the analysis code recorded
- [ ] `.env` snapshot (token removed) and image digest stored
- [ ] Raw JSONL archived read-only with per-file SHA256
- [ ] `/metrics` CSV archived
- [ ] `load_events.py` and `threat_report.py` run from a clean virtualenv on the archived data
- [ ] All figures regenerated by one command; no manual spreadsheet edits
- [ ] Synthetic data **not** present in the final database (IDs starting with `SYN-` absent)
- [ ] IPs aggregated (ASN/country) in published material; raw logs not published
