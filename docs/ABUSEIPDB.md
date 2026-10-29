# AbuseIPDB auto-reporting

BotBait can report the addresses that attack it to [AbuseIPDB](https://www.abuseipdb.com/), a public
blocklist database. It is **optional and off by default**; it turns on when `ABUSEIPDB_API_KEY` is set.

## Turn it on

1. Create a free account and copy the key from <https://www.abuseipdb.com/account/api>.
2. Either let `install.sh` ask for it (input is hidden and the key is checked against the API), or
   put it in `.env` and restart:

   ```bash
   sudo ./install.sh                                    # interactive prompt
   sudo ABUSEIPDB_API_KEY=... ./install.sh --yes        # non-interactive (keeps the key out of `ps`)
   # or edit .env, then:
   docker compose restart honeypot
   ```

   `install.sh --yes` on an existing installation reuses the key already saved in `.env`.
   `--no-abuseipdb` leaves everything as it is; `--skip-abuseipdb-check` skips the validation call.

The key lives in `.env` (mode 600) and is never logged; error messages have it redacted.

## What is reported, and what is not

An address is reported when a session shows **evidence of an attack**, not merely contact:

| Evidence | Reported |
|---|---|
| Confirmed exploit signature (Hikvision CVE-2017-7921 / 2021-36260 / 2025-34067, Dahua CVE-2021-33044 / 33045) | yes |
| Shell commands (T1059.004), malware download or upload (T1105), miner (T1496) | yes |
| Exploit request body: SOAP command injection, shell metacharacters, path traversal, PHP-CGI injection | yes |
| Password guessing only, two or more login attempts (T1110.001) | yes (category 18); no Telegram alert, since `HP_ALERT_ON_BRUTE` stays off. Set `HP_ABUSE_REPORT_BRUTE=false` to stop |
| A bare path such as `GET /.env`, crawlers, TLS or banner scanners, ADB handshake only | no |

Categories are chosen from the evidence: `15` Hacking and `20` Exploited Host for exploitation and shell
activity, `21` Web App Attack for HTTP exploits, `18` Brute-Force for guessing and `23`
IoT Targeted for the camera, ADB, Telnet and TR-069 services.

## Limits and politeness

* One report per address per `HP_ABUSE_WINDOW` (default `24h`, minimum `1h`). AbuseIPDB allows the same
  address once per 15 minutes; the longer window keeps your reports useful rather than repetitive.
* State is kept in `abuseipdb-state.json` next to the telemetry, so a restart does not re-report.
* The free plan allows 1000 reports per day. On HTTP 429 the sensor waits for `Retry-After`; if the wait
  is longer than 15 minutes (the daily limit) it pauses until then.
* HTTP 401/403 (revoked or wrong key) switches reporting off until the next restart; the sensor keeps
  running and alerting normally.
* Reports are queued and sent by one background worker with retries and back-off, so the network path
  and Telegram alerts never wait for AbuseIPDB. On shutdown the queue is drained within
  `HP_SHUTDOWN_TIMEOUT`.

## What the comment contains

For example: `BotBait IoT honeypot: Hikvision CVE-2021-36260 (webLanguage injection) on 80/HTTP. ATT&CK: T1059.004,
T1105, T1190. Dropper: hxxp://203[.]0[.]113[.]9:8080/a.sh. Sample SHA256: ...`

* No address of your server, no hostnames, no personal data.
* Links are defanged (`hxxp`, `[.]`) so nobody clicks malware by accident; control characters are removed;
  the comment is capped at 900 characters.

## Observability

* Event field `abuse_reported` in the JSONL log.
* Counters `honeypot_abuseipdb_reports_total`, `..._errors_total`, `..._skipped_total`.
* A line "Reported to AbuseIPDB: N IPs" in the weekly digest when N > 0.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `ABUSEIPDB_API_KEY` | empty | Key; empty = off |
| `HP_ABUSE_REPORT` | `true` | Set `false` to pause reporting without removing the key |
| `HP_ABUSE_REPORT_BRUTE` | `true` | Also report pure password guessing |
| `HP_ABUSE_WINDOW` | `24h` | Minimum time between two reports of the same address (min `1h`) |
| `HP_ABUSE_STATE` | `<HP_LOG_DIR>/abuseipdb-state.json` | State file; `off` disables it |

## Be a good citizen

Read AbuseIPDB's [terms](https://www.abuseipdb.com/terms) and [API documentation](https://docs.abuseipdb.com/).
Reports are public attribution about an address, and a wrong report harms a third party, which is why only
payload-level evidence is sent. Shared hosting and carrier-grade NAT can make one address stand for many
people; keep that in mind before acting on any blocklist.
