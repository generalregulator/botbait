# %% [markdown]
# # Honeypot Threat Intelligence Report
#
# Reproducible analysis of the JSONL telemetry collected by the Go honeypot.
# Run as a script (`python threat_report.py`, figures + `summary.md` are written
# to `figures/`) or open as a notebook (`python build_notebook.py` creates
# `threat_report.ipynb` from this file).
#
# Inputs: SQLite database produced by `load_events.py`
# (`HP_DB`, default `../data/honeypot.sqlite`).
#
# **Caveat:** every statistic is a property of *this sensor* (one IP, one
# network, one period) - see "Threats to validity" in the project docs.

# %%
import os
import re
import sqlite3
import sys
from urllib.parse import urlparse

import matplotlib
import pandas as pd

if "ipykernel" not in sys.modules:  # headless when run as a script
    matplotlib.use("Agg")
import matplotlib.pyplot as plt

DB = os.environ.get("HP_DB", "../data/honeypot.sqlite")
OUT = os.environ.get("HP_FIG_DIR", "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"figure.dpi": 110, "axes.spines.top": False, "axes.spines.right": False})

con = sqlite3.connect(DB)
ev = pd.read_sql_query("SELECT * FROM events", con)
ev["ts"] = pd.to_datetime(ev["ts"], utc=True, format="ISO8601")
tech = pd.read_sql_query("SELECT * FROM event_techniques", con)
iocs = pd.read_sql_query("SELECT * FROM event_iocs", con)
dl = pd.read_sql_query("SELECT * FROM downloads", con)
cred = pd.read_sql_query("SELECT * FROM credentials", con)
try:
    drops = pd.read_sql_query("SELECT * FROM dropped_files", con)
except Exception:  # database created by an older loader
    drops = pd.DataFrame(columns=["event_id", "path", "via", "success", "sha256", "file_type", "size", "executable"])
cmds = pd.read_sql_query("SELECT * FROM commands", con)
if ev.empty:
    raise SystemExit("database contains no events")

summary: list[str] = []


def savefig(name: str) -> None:
    plt.tight_layout()
    plt.savefig(os.path.join(OUT, name + ".png"))
    if "ipykernel" in sys.modules:
        plt.show()
    plt.close()


def md_table(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    rows = ["| " + " | ".join(map(str, cols)) + " |", "|" + "---|" * len(cols)]
    rows += ["| " + " | ".join(str(v) for v in r) + " |" for r in df.itertuples(index=False)]
    return "\n".join(rows)


def section(title: str, df: pd.DataFrame | None = None, note: str = "") -> None:
    summary.append(f"\n## {title}\n")
    if note:
        summary.append(note + "\n")
    if df is not None and not df.empty:
        summary.append(md_table(df) + "\n")


# %% [markdown]
# ## 1. Overview

# %%
period = f"{ev.ts.min():%Y-%m-%d} -> {ev.ts.max():%Y-%m-%d}"
n_events, n_ips = len(ev), ev.src_ip.nunique()
n_attack = tech.event_id.nunique()
cap_ok = int(dl.success.sum()) if not dl.empty else 0
overview = pd.DataFrame({
    "metric": ["Period (UTC)", "Events (sessions)", "Unique source IPs", "Events with >=1 ATT&CK technique",
               "Payload URLs attempted", "Payloads captured", "Unique payload SHA256"],
    "value": [period, n_events, n_ips, f"{n_attack} ({n_attack / n_events:.1%})", len(dl), cap_ok,
              dl.sha256.nunique() if not dl.empty else 0],
})
print(overview.to_string(index=False))
section("Overview", overview)

# %% [markdown]
# ## 2. Activity over time

# %%
daily = ev.groupby([ev.ts.dt.date, "protocol"]).size().unstack(fill_value=0)
ax = daily.plot(kind="bar", stacked=True, figsize=(10, 4))
ax.set(title="Sessions per day by protocol", xlabel="Day (UTC)", ylabel="Sessions")
savefig("01_daily_by_protocol")

# %% [markdown]
# ## 3. Who is attacking: ASN and country distribution
# Measured two ways: *sessions* (volume) and *unique source IPs* (breadth).
# A single noisy host can dominate the first; the second approximates how many
# infected devices an AS hosts.

# %%
ev["asn_label"] = (ev.asn.fillna("unresolved") + " " + ev.isp.fillna("")).str.strip()
asn = (ev.groupby("asn_label").agg(sessions=("id", "count"), unique_ips=("src_ip", "nunique"))
       .sort_values("sessions", ascending=False))
asn["share_%"] = (asn.sessions / asn.sessions.sum() * 100).round(1)
asn["cum_share_%"] = asn["share_%"].cumsum().round(1)
top = asn.head(15)
ax = top.iloc[::-1].plot(kind="barh", y=["sessions", "unique_ips"], figsize=(9, 6))
ax.set(title="Top 15 ASNs: sessions vs unique source IPs", xlabel="count", ylabel="")
savefig("02_top_asn")
section("Top ASNs", top.reset_index().head(10),
        f"Top-5 ASNs account for {asn['share_%'].head(5).sum():.1f}% of sessions.")

country = ev.groupby(ev.country.fillna("Unknown")).agg(sessions=("id", "count"), unique_ips=("src_ip", "nunique")) \
    .sort_values("sessions", ascending=False).head(10)
country.iloc[::-1].plot(kind="barh", y="sessions", legend=False, figsize=(8, 4),
                        title="Top 10 source countries (by sessions)")
savefig("03_top_countries")
section("Top countries", country.reset_index())

# %% [markdown]
# ## 4. What they target: service and protocol mix

# %%
svc = ev.groupby(["dst_port", "protocol"]).size().rename("sessions").reset_index() \
    .sort_values("sessions", ascending=False)
svc["label"] = svc.dst_port.astype(str) + "/" + svc.protocol
svc.set_index("label").sessions.plot(kind="bar", figsize=(8, 3.5), title="Sessions by destination port/protocol")
savefig("04_service_mix")

# %% [markdown]
# ## 5. What they do: MITRE ATT&CK technique frequency

# %%
if not tech.empty:
    tcount = (tech.groupby(["technique_id", "technique_name"]).event_id.nunique().rename("events")
              .reset_index().sort_values("events", ascending=False))
    tcount["share_of_events_%"] = (tcount.events / n_events * 100).round(1)
    tcount.assign(label=tcount.technique_id + "\n" + tcount.technique_name.str.slice(0, 22)) \
        .set_index("label").events.plot(kind="bar", figsize=(10, 4), rot=0, title="Events per ATT&CK technique")
    savefig("05_mitre_techniques")
    section("MITRE ATT&CK techniques", tcount)
    # Co-occurrence: typical kill-chain combinations.
    combos = (tech.sort_values("technique_id").groupby("event_id").technique_id.apply(lambda s: " + ".join(s))
              .value_counts().head(8).rename_axis("technique_combination").reset_index(name="events"))
    section("Most common technique combinations", combos)

# %% [markdown]
# ## 6. When: hour-of-day x weekday (UTC)

# %%
heat = ev.groupby([ev.ts.dt.dayofweek, ev.ts.dt.hour]).size().unstack(fill_value=0) \
    .reindex(index=range(7), columns=range(24), fill_value=0)
fig, ax = plt.subplots(figsize=(10, 3.2))
im = ax.imshow(heat.values, aspect="auto", cmap="viridis")
ax.set(yticks=range(7), yticklabels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
       xticks=range(0, 24, 2), xlabel="Hour (UTC)", title="Sessions by weekday and hour")
fig.colorbar(im, ax=ax, label="sessions")
savefig("06_hour_weekday_heatmap")

# %% [markdown]
# ## 7. Credentials tried (Telnet)

# %%
if not cred.empty:
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    cred.username.value_counts().head(10).iloc[::-1].plot(kind="barh", ax=axes[0], title="Top usernames")
    cred.password.value_counts().head(10).iloc[::-1].plot(kind="barh", ax=axes[1], title="Top passwords")
    savefig("07_credentials")
    pairs = (cred.username.fillna("") + " / " + cred.password.fillna("")).value_counts().head(10) \
        .rename_axis("username / password").reset_index(name="attempts")
    section("Top credential pairs", pairs)

# %% [markdown]
# ## 8. Payload infrastructure and malware triage
# Family labels below are **heuristics** (file-name hints and architecture
# suffixes). Treat them as a first pass; confirm hashes against a
# multi-engine service (e.g. VirusTotal) and/or YARA before naming a family.

# %%
FAMILY_HINTS = [
    (r"mozi", "Mozi (name hint)"),
    (r"(mirai|miori|okiru|satori|masuta|sora|hajime|gafgyt|bashlite|qbot|tsunami|kaiten)",
     lambda m: m.group(1).capitalize() + " (name hint)"),
    (r"(xmrig|minerd|cpuminer|miner)", "Coin miner (name hint)"),
    (r"\.(arm\d?|mips(el)?|mpsl|mps|x86(_64)?|i[3-6]86|ppc|sh4|m68k|spc|arc|aarch64)$",
     "IoT botnet binary (arch-suffixed)"),
    (r"\.sh$", "Shell dropper script"),
]


def family(url: str, ftype: str | None) -> str:
    path = urlparse(url).path.lower()
    for pat, label in FAMILY_HINTS:
        m = re.search(pat, path)
        if m:
            return label(m) if callable(label) else label
    return f"Unlabelled ({ftype or 'unknown type'})"


if not dl.empty:
    dl["host"] = dl.url.map(lambda u: urlparse(u).hostname)
    dl["family"] = [family(u, t) for u, t in zip(dl.url, dl.file_type)]

    status = dl.status.value_counts().rename_axis("status").reset_index(name="count")
    status.set_index("status")["count"].iloc[::-1].plot(kind="barh", figsize=(9, 3), title="Payload download outcomes")
    savefig("08_download_status")
    section("Download outcomes (dead-link rate is itself a finding)", status)

    got = dl[dl.success == 1].drop_duplicates("sha256")
    if not got.empty:
        fam = got.family.value_counts().rename_axis("family (heuristic)").reset_index(name="unique samples")
        fam.set_index("family (heuristic)")["unique samples"].iloc[::-1].plot(
            kind="barh", figsize=(9, 3.5), title="Unique captured samples by heuristic family")
        savefig("09_families")
        section("Unique samples by heuristic family", fam,
                "Heuristic labels from file names only; verify with VirusTotal/YARA.")
        ftypes = got.file_type.value_counts().rename_axis("file type").reset_index(name="unique samples")
        section("Captured file types", ftypes)

    hosts = (dl.groupby("host").agg(urls=("url", "nunique"), attempts=("url", "count"),
                                    unique_samples=("sha256", "nunique"))
             .sort_values("attempts", ascending=False).head(10).reset_index())
    section("Top payload-hosting addresses", hosts)

    # Campaign view: one payload URL served to many distinct victims-turned-scanners.
    camp = dl.merge(ev[["id", "src_ip"]], left_on="event_id", right_on="id") \
        .groupby("url").agg(distinct_sources=("src_ip", "nunique"), events=("event_id", "nunique")) \
        .sort_values("distinct_sources", ascending=False).head(10).reset_index()
    section("Payload URLs seen from the most distinct source IPs (campaign indicator)", camp)

# %% [markdown]
# ## 9. Files left on the device: `adb push` and echo-assembled droppers
# These samples arrive *without any URL*: they are pushed over the ADB sync
# protocol or rebuilt byte by byte in the shell. They are therefore invisible
# to download-based statistics and form a separate delivery channel.

# %%
if not drops.empty:
    by_via = (drops.groupby("via").agg(files=("sha256", "size"), captured=("success", "sum"),
                                       unique_samples=("sha256", "nunique"))
              .sort_values("files", ascending=False).reset_index())
    section("Dropped files by delivery method", by_via,
            "Compare with the URL-download channel: samples that are pushed never touch a payload host.")

    got_d = drops[drops.success == 1].drop_duplicates("sha256")
    if not got_d.empty:
        fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
        got_d.file_type.value_counts().iloc[::-1].plot(kind="barh", ax=axes[0], title="Pushed/assembled: file types")
        axes[0].set_ylabel("")
        names = got_d.path.map(lambda p: str(p).rsplit("/", 1)[-1]).value_counts().head(10)
        names.iloc[::-1].plot(kind="barh", ax=axes[1], title="File names chosen by attackers")
        axes[1].set_ylabel("")
        savefig("10_dropped_files")
        section("Attacker-chosen file names (campaign fingerprints)",
                names.rename_axis("file name").reset_index(name="events"))

    # Delivery channel overlap: how many unique samples were seen only via push?
    url_sha = set(dl.sha256.dropna()) if not dl.empty else set()
    push_sha = set(drops.sha256.dropna())
    section("Delivery channels", pd.DataFrame({
        "channel": ["URL download only", "push / shell-write only", "both"],
        "unique samples": [len(url_sha - push_sha), len(push_sha - url_sha), len(url_sha & push_sha)],
    }))

# %% [markdown]
# ## 10. Command vocabulary (ADB / Telnet shell)
# The first word of every command typed in an emulated shell. A small, stable
# vocabulary indicates scripted bots; a long tail indicates humans or newer tools.

# %%
if not cmds.empty:
    first = cmds.command.str.strip().str.split(r"[\s;|&]+", n=1, regex=True).str[0] \
        .str.rsplit("/", n=1).str[-1].replace("", pd.NA).dropna()
    vocab = first.value_counts().head(15).rename_axis("command").reset_index(name="count")
    vocab.set_index("command")["count"].iloc[::-1].plot(kind="barh", figsize=(8, 4.5), title="Most common shell commands")
    savefig("11_command_vocabulary")
    section("Command vocabulary", vocab,
            f"{first.nunique()} distinct commands across {cmds.event_id.nunique()} shell sessions.")

# %% [markdown]
# ## 11. Write the summary

# %%
with open(os.path.join(OUT, "summary.md"), "w", encoding="utf-8") as fh:
    fh.write("# Honeypot telemetry summary\n\n_Generated by `threat_report.py`._\n")
    fh.write("\n".join(summary))
print(f"figures and summary.md written to {os.path.abspath(OUT)}")
