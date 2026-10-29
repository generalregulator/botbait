# Camera and DVR web personas

BotBait serves three web "devices" next to the ADB, TR-069 and Telnet listeners.
They exist because camera and DVR botnets (Mirai descendants) attack the vendor
web interface, not the management ports above. Like everything in BotBait they
are **emulation only**: no PHP, shell command or uploaded file is ever executed.

| Host port | Container port | Persona | Chosen by |
|---|---|---|---|
| `80` | `8088` | Hikvision network camera | `HP_WEB_PORTS` |
| `81` | `8081` | TVT NVMS-9000 DVR | `HP_WEB_PORTS` |
| `8080` | `8080` | Dahua camera | `HP_WEB_PORTS` |

The persona decides the *root page*. A request whose path belongs to another
vendor (for example `/RPC2_Login` on the Hikvision port) is answered by that
vendor's persona, because scanners spray every path at every port.
`HP_PORT_LABELS` makes alerts and telemetry show the public port (`80/HTTP`)
instead of the container port (`8088`). Serial numbers, MAC addresses and the
device ID are derived from the per-deployment profile seed, so two sensors do
not share a fingerprint.

## What is recognised

Every recognised exploit pattern sets the event's `signature` field, which is
shown in the alert as `[HTTP PUT | Hikvision CVE-2021-36260 (webLanguage injection)]`,
is mapped to ATT&CK `T1190`, and appears in the weekly digest under *Exploit Signatures*.

| Persona | Request | Behaviour | Signature |
|---|---|---|---|
| Hikvision | `PUT /SDK/webLanguage` with an injected `<language>` value | `200` with an ISAPI `ResponseStatus`; commands inside `$(...)` or backticks are recorded in `commands`, URLs in them are downloaded and hashed by the normal pipeline | `Hikvision CVE-2021-36260 (webLanguage injection)` |
| Hikvision | `GET /System/deviceInfo`, `/Security/users`, `/System/configurationFile`, `/onvif-http/snapshot` (also under `/ISAPI/`) with `auth=YWRtaW46MTEK` | Returns plausible fake data (device info XML, one `admin` user, an 8 KiB opaque blob, a tiny JPEG) | `Hikvision CVE-2017-7921 (auth parameter bypass)` |
| Hikvision | `POST /bic/ssoService/v1/applyCT` with a JSON body that carries a fastjson `@type` key and a JNDI-style URL (`ldap://`, `rmi://`, ...) | `200` JSON `{"code":"200","msg":"success"}`; nothing is resolved or fetched | `Hikvision CVE-2025-34067 (applyCT fastjson deserialization)` |
| Hikvision | the same paths without that token or credentials | `401` with a Digest challenge | none |
| Dahua | `POST /RPC2_Login` | First call without a password: login challenge (`realm`, `random`); with a password: success. User name and password are stored as credentials | none |
| Dahua | `POST /RPC2_Login` with client type `NetKeyboard` | Success without a password | `Dahua CVE-2021-33044 (NetKeyboard login bypass)` |
| Dahua | `POST /RPC2_Login` mentioning `Loopback` or `127.0.0.1` | Success without a password | `Dahua CVE-2021-33045 (loopback login bypass)` |
| Dahua | `POST /RPC2` (`magicBox.getSystemInfo`, ...) | JSON reply with the persona's serial number | none |
| Dahua | `GET /cgi-bin/magicBox.cgi`, `userManager.cgi`, ... | `401` Digest challenge; with any `Authorization` header a short plain-text reply | none |
| TVT | `GET /` | NVMS-9000 login page | none |
| any | `Authorization: Basic` / `Digest` | The user name (and the Basic password) is stored as a credential | none |

## How a request is confirmed (and why crawlers never alert)

Alerts are raised for events carrying an ATT&CK technique such as `T1190`. On
the camera and DVR ports the sensor is deliberately strict about that:

1. **Only a confirmed signature or real injection counts.** A signature is set
   only when the request matches the documented abuse pattern exactly:
   * Hikvision CVE-2017-7921: `GET` with the documented token `auth=YWRtaW46MTEK`
     on one of the known paths. Any other `auth` value gets a `401`, so a
     crawler or a guesser is not confirmed and is not served data.
   * Hikvision CVE-2021-36260: `PUT /SDK/webLanguage` whose `<language>` value
     contains command substitution (`$(...)`, backticks) or `;` / `|`. A
     harmless `<language>en</language>`, a `POST` or a `GET` is not confirmed.
   * Dahua CVE-2021-33044 / 33045: a `POST /RPC2_Login` whose JSON parses, has
     `method` equal to `global.login` and `clientType` equal to `NetKeyboard` or
     `Loopback` (or `ipAddr` equal to `127.0.0.1`). The words appearing somewhere
     else in the body do not count.
   * Hikvision CVE-2025-34067: `POST /bic/ssoService/v1/applyCT` whose body is
     valid JSON, contains an `@type` key at any depth and a string value that is an
     `ldap`, `ldaps`, `rmi`, `iiop` or `dns` URL. Anything else on that path gets the
     same reply but no signature.
2. **Path guesses are ignored.** The generic "suspicious path" rules (`/cgi-bin/`,
   `/.env`, `/wp-content/plugins/`, `/actuator`, ...) are switched off on camera
   ports, because that is what crawlers and generic scanners request. The
   remaining generic rules need actual payload evidence: a SOAP exploit body,
   command substitution, a `;wget ...` / `|sh` chain, path traversal.
3. **Query parameters that merely look like shell words** (`?a=1&cd=2`,
   `&sh=0`, `&nc=5`) no longer count: a command word must be followed by a space,
   `+` or `${IFS}`.
4. Everything is still **logged**: crawler requests appear in the JSONL telemetry
   with the persona that answered (`persona`) but without techniques or a
   signature, so they never reach Telegram and never count as attacks in the
   weekly digest.

A confirmed signature does not depend on which port it arrived on: a Hikvision
exploit sent to the Dahua port is still a Hikvision exploit attempt, and the
alert shows the real port. The signature names the pattern that was *sent*; the
sensor cannot prove that the sender was an exploit tool and not a researcher.

## What is honestly approximate

* **TVT is thin.** Public reporting says Mirai variants attack TVT NVMS-9000 DVRs,
  but the sources I found do not name the HTTP endpoint or parameters, and the
  reported credential-disclosure flaw is in a binary protocol on another port.
  The TVT persona is therefore a login page plus full request recording, with no
  exploit-specific behaviour and no signature. A TCP persona for that protocol is
  future work.
* **Response bodies are plausible, not byte-exact.** Banners (`Server: App-webs/`,
  `Webs`, `nginx`), login pages (written from scratch, no vendor assets), firmware
  strings and JSON shapes were chosen to look right to a scanner, not copied from
  real devices. A fingerprinting tool such as Shodan or a careful human will
  tell them apart from the real thing. Compare with a real device before relying
  on them for sensor-bias claims.
* **Signatures describe the *pattern*, not proof of an exploit.** A request that
  carries the documented token is labelled CVE-2017-7921 because that is the
  documented way the flaw is abused; the sensor cannot know the author's intent.
  Variants that use a different token or encoding are not confirmed (they are
  logged and answered with `401`).
* The Dahua login-bypass signatures match on the client type / loopback address in
  the request body, based on public descriptions of CVE-2021-33044 and
  CVE-2021-33045.

## Coverage of the latest variants

| Vulnerability | Status in BotBait |
|---|---|
| Hikvision CVE-2017-7921 (auth bypass, CISA KEV, Mar 2026) | Matched (HTTP) |
| Hikvision CVE-2021-36260 (`webLanguage` injection, Moobot/Mirai) | Matched (HTTP) |
| Hikvision CVE-2025-34067 (HikCentral `applyCT`, fastjson) | Matched (HTTP). Affects the Hikvision Integrated Security Management Platform (HikCentral), not cameras; unauthenticated `POST` with a JSON body; exploitation observed by the Shadowserver Foundation (NVD record), not in CISA KEV. A hit on a camera persona is a scanner spraying the platform exploit |
| Dahua CVE-2021-33044 / 33045 (CISA KEV, "CameraSwarm", Jul-Aug 2026) | Matched on the HTTP JSON-RPC login. Reported attacks run mostly over the Easy4IP binary protocol on TCP/37777, which is **not** emulated |
| Dahua CVE-2025-31700 / 31701 (ONVIF and RPC upload overflows) | Not matched: disclosed, no reported exploitation, and reliable recognition needs binary payload analysis |
| Dahua Easy4IP cloud relay abuse, brute force on 37777, CVE-2025-31702 | Not HTTP and not emulated (TCP/37777 binary protocol); out of scope for the web personas |
| GPON / Dasan home gateways CVE-2018-10561 / 10562 | Not emulated (out of scope). The generic rules still record a `diag_Form` command injection (shell words, `;wget`), but there is no GPON-specific signature |
| TBK DVR CVE-2024-3721, D-Link DIR-823X CVE-2025-29635, TP-Link AX21 CVE-2023-1389 (Nexcorium / tuxnokill, April 2026) | Not matched by name: the sources do not give the request paths. Command injection in a parameter is caught by the generic rules (shell words, `$(...)`, `;wget`), but the sensor does not emulate these devices |
| TVT NVMS-9000 | No public HTTP endpoint; login page and recording only |

"Matched" means a strict, documented pattern; see above. New variants are added only
with a public description of the request shape.

## Sources

* Fortinet, [Moobot targets a Hikvision vulnerability](https://www.fortinet.com/blog/threat-research/mirai-based-botnet-moobot-targets-hikvision-vulnerability) (CVE-2021-36260, `<language>` tag injection)
* SANS ISC, [Exploit attempts against an older Hikvision camera vulnerability](https://isc.sans.edu/diary/32316) (CVE-2017-7921 request pattern and paths, September 2025)
* The Hacker News, [Hackers compromised 14,500 Dahua devices](https://thehackernews.com/2026/08/hackers-compromised-14500-dahua-devices.html) (CVE-2021-33044 / CVE-2021-33045, August 2026)
* TechRadar, [TVT DVRs become prime target for Mirai botnet](https://www.techradar.com/pro/security/tvt-dvrs-become-prime-target-for-mirai-botnet) (NVMS-9000 authentication bypass, fixed in 1.3.4)
* Hunt.io, Operation CameraSwarm (Dahua toolkit: CVE-2021-33044/33045 over TCP/37777, brute force, cloud relay, August 2026)
* SANS ISC diary 32886 (compromised Dahua-OEM DVR: Telnet default credentials, no CVE)
* NVD / Tenable, [CVE-2025-34067](https://www.tenable.com/cve/CVE-2025-34067) (Hikvision Integrated Security Management Platform, `/bic/ssoService/v1/applyCT`, Fastjson auto-type deserialization; Shadowserver exploitation observed 2025-02-05)
