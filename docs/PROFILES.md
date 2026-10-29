# Device profiles ("legends")

A *profile* is the identity the honeypot presents to an attacker who gets past
the handshake: what `getprop`, `uname -a`, `cat /proc/cpuinfo`, `ps`,
`pm list packages`, `ls` and friends return, which commands exist, and how the
Telnet login dialogue looks. Profiles are **data only**: plain JSON, strictly
decoded (unknown fields are an error), size-bounded and validated at start-up.
A profile can never cause anything to be executed.

Built-in profiles (embedded in the binary):

| Name | Kind | Persona |
|---|---|---|
| `android-tvbox` (default for ADB) | `android` | Amlogic S905X TV box, Android 7.1.2, hostname `p212`, BusyBox 1.26.2 under `/system/xbin`, no plain `wget`/`curl` (as on real boxes) |
| `router-busybox` (suggested for Telnet) | `router` | Realtek RTL8196C MIPS home router, Linux 2.6.30.9, BusyBox 1.22.1, `# ` prompt, first Telnet login rejected |

```bash
honeypot -list-profiles
honeypot -check-profile router-busybox
honeypot -check-profile ./profiles/my-dvr.json
```

## Selecting a profile

| Variable | Meaning |
|---|---|
| `HP_PROFILE` | Persona for ADB (and for Telnet when `HP_TELNET_PROFILE` is empty). Built-in name or path to a JSON file. |
| `HP_TELNET_PROFILE` | Separate persona for Telnet. Empty = same as `HP_PROFILE`. |
| `HP_PROFILE_SEED` | Seed for the per-deployment identifiers. Empty = random, generated once and persisted in `HP_LOG_DIR/profile.seed` (mode 0600). |

**One persona or two?** A single IP that speaks ADB as an Android TV box and
Telnet as a Realtek router is incoherent to an attacker who correlates banners
(and to a scanner such as Shodan). Two personas, however, yield better data
yield on mixed botnets, because Mirai-class Telnet bots expect BusyBox. The
shipped `.env.example` uses two personas; set `HP_TELNET_PROFILE=` (empty)
for a coherent single device. Decide according to your research question and
write it in your methodology.

To use a custom profile with Docker Compose, mount it read-only and point the
variable at the container path:

```yaml
    volumes:
      - ./profiles:/app/profiles:ro
```
```
HP_PROFILE=/app/profiles/my-dvr.json
```

## Anti-fingerprinting: placeholders

A honeypot that returns byte-identical serials, MACs and Android IDs on every
install is trivially discoverable. Never hard-code identifiers; use these
placeholders, which are expanded at load time from the deployment seed:

| Placeholder | Expands to |
|---|---|
| `{{serial}}` | 16 hex chars |
| `{{android_id}}` | 16 hex chars |
| `{{mac}}` | MAC with the profile's `oui` prefix and 3 random octets |
| `{{ip}}` | plausible RFC 1918 address (`192.168.x.y`) |
| `{{suffix}}` | 4 hex chars (e.g. for hostnames like `DVR-{{suffix}}`) |
| `{{hostname}}` | the (expanded) `hostname` field |

Runtime placeholders resolved by the shell: `{{cwd}}`, `{{user}}` (prompt only).

Further advice: vary the uptime base (`uptime_base_sec`), keep package lists and
build dates mutually consistent, avoid strings that appear on honeypot-detection
lists, and rotate or customise the profile for every public deployment.

## Schema

```jsonc
{
  "name": "my-dvr",                // [a-z0-9_-], <= 48 chars, required
  "description": "free text",
  "kind": "router",                // "android" | "router"
  "hostname": "DVR-{{suffix}}",    // required, [A-Za-z0-9{}_.-]
  "oui": "bc:ad:28",               // first 3 MAC octets (optional)

  "shell": {
    "user": "root", "uid": 0, "home": "/root",
    "path": "/usr/sbin:/usr/bin:/sbin:/bin",
    "prompt": "{{cwd}} # ",
    "not_found": "-sh: %s: not found"      // must contain one %s
  },
  "adb": { "features": "shell_v2,cmd,stat_v2" },  // advertised in CNXN
  "telnet": {
    "pre": "", "login_prompt": "DVR login: ", "password_prompt": "Password: ",
    "failure_message": "Login incorrect", "failures_before_accept": 1,   // 0..5
    "welcome": "\nWelcome\n", "prompt": "# "
  },
  "kernel": { "sysname": "Linux", "release": "3.0.8", "version": "#1 SMP ...",
              "machine": "armv7l", "os": "GNU/Linux" },
  "busybox": { "present": true, "version": "1.22.1",
               "banner": "BusyBox v1.22.1 (2016-05-02) multi-call binary.",
               "applets": ["cat", "ls", "wget"] },

  "props":    { "ro.product.model": "X" },        // Android getprop
  "packages": ["com.android.settings"],           // pm list packages
  "proc":     { "cpuinfo": "...", "version": "..." },   // /proc/<key>
  "files":    { "/etc/passwd": "root:x:0:0::/root:/bin/sh\n" },
  "dirs":     ["/mnt/mtd"],
  "bins":     ["ls", "cat", "echo"],              // commands that "exist"
  "processes": [{ "pid": 1, "ppid": 0, "user": "root", "vsize": 1820, "rss": 540, "name": "init" }],
  "commands": { "cat /proc/mtd": "dev: size erasesize name\n..." },  // exact line -> stdout
  "uptime_base_sec": 864000
}
```

Limits (enforced by `Validate`): file <= 1 MiB; <= 300 `files`, each <= 64 KiB;
<= 1500 `props`; <= 2000 entries per list; paths must be clean and absolute;
`bins`/`applets` are bare names.

### Scripting behaviour for specific commands and uploaded files

`commands` maps a command line to its stdout; the longest matching prefix wins.
Keys may also be **paths**, so you can script what an uploaded file prints:

```json
"commands": { "./bot": "listening tun0\n", "/data/local/tmp/x": "" }
```

`exec_rules` is the structured form for files the attacker uploaded or wrote.
The first rule whose conditions all match is used (conditions: `path` regexp,
`file_type` as detected from the content, `sha256`); at least one is required.

```json
"exec_rules": [
  { "sha256": "9c1e...64 hex...", "stdout": "listening tun0\n" },
  { "file_type": "ELF", "path": "^/data/local/tmp/", "stdout": "", "stderr": "", "exit": 0 }
]
```

Without a matching rule an uploaded binary runs silently with exit status 0, and
an uploaded shell script is *interpreted* by the emulator (so URLs inside become
indicators). Nothing is ever executed. Limits: 50 rules, 4 KiB per output,
regexp at most 256 characters.

### Content of binaries

Device binaries (`/bin/busybox`, `/system/bin/*`, `/proc/self/exe`) read as a
synthetic ELF image whose header (class, endianness, `e_machine`) is derived
from `kernel.machine`: `armv7l`, `aarch64`, `mips`/`mipsel`, `x86_64`, `i686`,
`ppc*`, `sh*`. The filler is deterministic, so checksums are stable across
sessions. A verbatim copy of such an image (`cp /bin/echo x`, `cat /bin/echo > x`)
is not reported as a sample.

Inspection commands available (when the profile lists them in `bins`):
`dd`, `head -c`, `tail -c`, `od`, `hexdump`, `xxd`, `strings`, `file`,
`md5sum`, `sha1sum`, `sha256sum`.

### How commands are answered

1. `commands`: the exact command line, then successively shorter prefixes.
2. Built-in emulation of ~150 command names. Around 60 produce profile-driven
   output or change the virtual file system (`ls`, `cat`, `uname`, `id`, `ps`,
   `getprop`, `pm`, `echo`, `base64`, `chmod`, `rm`, `cp`, `wget`/`curl`
   (pretended), ...); the rest (`tar`, `sed`, `iptables`, ...) succeed silently,
   which is what most bot scripts need. Add exact outputs in `commands` where
   a script's behaviour depends on them.
3. Anything whose name is not in `bins`/`busybox.applets` prints `shell.not_found`.

The emulator never executes anything: `wget`/`curl`/`tftp`/`ftpget` produce a
plausible transcript while the real, SSRF-guarded fetch is done later by the
asynchronous downloader.

## Authoring checklist

* Start from a real device you own or public documentation, never from a
  leaked firmware image with embedded secrets or licensed content.
* Capture real `uname -a`, `cat /proc/cpuinfo`, `cat /proc/version`,
  `busybox`, `ps`, `mount`, `ls -la /` outputs from the device; paste them in.
* Use placeholders for every identifier.
* `honeypot -check-profile ./my-dvr.json`, then `go test ./internal/profile`
  if you are contributing it upstream.
* Connect to a test instance with `adb connect` / `telnet` and run what bots
  run: `cat /proc/cpuinfo`, `uname -a`, `busybox <RANDOM>`, `ps`, `ls /`,
  `id`, `which wget curl tftp`.
