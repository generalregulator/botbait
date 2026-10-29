#!/usr/bin/env python3
"""Load honeypot JSONL logs into a normalised SQLite database.

Usage:
    python load_events.py ../data --db ../data/honeypot.sqlite

The loader is idempotent (INSERT OR REPLACE keyed by event id), so it can be
re-run on a growing log directory. Malformed lines are counted, not fatal.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3
import sys
from typing import Iterable, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,          -- UTC, RFC 3339
    src_ip          TEXT NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER NOT NULL,
    protocol        TEXT NOT NULL,          -- HTTP | ADB | TELNET | RAW
    action          TEXT,
    http_method     TEXT,
    http_path       TEXT,
    user_agent      TEXT,
    bytes_received  INTEGER,
    truncated       INTEGER,
    session_ms      INTEGER,
    country         TEXT,
    country_code    TEXT,
    isp             TEXT,
    asn             TEXT,
    as_name         TEXT,
    geo_resolved    INTEGER,
    alert_sent      INTEGER,
    n_commands      INTEGER,
    payload         TEXT,
    signature       TEXT
);
CREATE TABLE IF NOT EXISTS event_techniques (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,
    technique_name TEXT,
    PRIMARY KEY (event_id, technique_id)
);
CREATE TABLE IF NOT EXISTS event_iocs (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                     -- url | download_url | ip | domain
    value TEXT NOT NULL,
    PRIMARY KEY (event_id, kind, value)
);
CREATE TABLE IF NOT EXISTS downloads (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    status TEXT,
    success INTEGER,
    cached INTEGER,
    sha256 TEXT,
    file_type TEXT,
    content_type TEXT,
    size INTEGER,
    duration_ms INTEGER,
    PRIMARY KEY (event_id, url)
);
CREATE TABLE IF NOT EXISTS credentials (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    username TEXT,
    password TEXT
);
CREATE TABLE IF NOT EXISTS commands (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    command TEXT NOT NULL,
    PRIMARY KEY (event_id, seq)
);
CREATE TABLE IF NOT EXISTS dropped_files (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    path TEXT,
    via TEXT,                               -- adb-sync-push | shell-write
    mode TEXT,
    status TEXT,
    success INTEGER,
    incomplete INTEGER,
    executable INTEGER,
    sha256 TEXT,
    file_type TEXT,
    size INTEGER,
    PRIMARY KEY (event_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src  ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_asn  ON events(asn);
CREATE INDEX IF NOT EXISTS idx_dl_sha      ON downloads(sha256);
CREATE INDEX IF NOT EXISTS idx_drop_sha    ON dropped_files(sha256);
CREATE INDEX IF NOT EXISTS idx_tech        ON event_techniques(technique_id);
"""


def resolve_files(inputs: Iterable[str]) -> list[str]:
    files: list[str] = []
    for item in inputs:
        if os.path.isdir(item):
            files += glob.glob(os.path.join(item, "**", "*.jsonl"), recursive=True)
        else:
            files += glob.glob(item)
    return sorted(set(files))


def iter_events(files: list[str]) -> Iterator[tuple[dict, int]]:
    """Yield (event, bad_lines_so_far)."""
    bad = 0
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line), bad
                except json.JSONDecodeError:
                    bad += 1


def b(v) -> int:
    return 1 if v else 0


def insert_event(cur: sqlite3.Cursor, e: dict) -> None:
    geo = e.get("geo") or {}
    iocs = e.get("iocs") or {}
    eid = e["id"]
    # REPLACE semantics for the whole event (children are re-inserted below).
    for t in ("event_techniques", "event_iocs", "downloads", "credentials", "commands", "dropped_files"):
        cur.execute(f"DELETE FROM {t} WHERE event_id = ?", (eid,))
    cur.execute(
        "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            eid, e["timestamp"], e["src_ip"], e.get("src_port"), e["dst_port"],
            e["protocol"], e.get("action"), e.get("http_method"), e.get("http_path"),
            e.get("user_agent"), e.get("bytes_received"), b(e.get("truncated")),
            e.get("session_duration_ms"), geo.get("country"), geo.get("country_code"),
            geo.get("isp"), geo.get("asn"), geo.get("as_name"), b(geo.get("resolved")),
            b(e.get("alert_sent")), len(e.get("commands") or []), e.get("payload"), e.get("signature"),
        ),
    )
    cur.executemany(
        "INSERT OR IGNORE INTO event_techniques VALUES (?,?,?)",
        [(eid, t["id"], t.get("name")) for t in e.get("mitre") or []],
    )
    rows = []
    for kind, key in (("url", "urls"), ("download_url", "download_urls"),
                      ("ip", "ips"), ("domain", "domains")):
        rows += [(eid, kind, v) for v in iocs.get(key) or []]
    cur.executemany("INSERT OR IGNORE INTO event_iocs VALUES (?,?,?)", rows)
    cur.executemany(
        "INSERT OR IGNORE INTO downloads VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(eid, d["url"], d.get("status"), b(d.get("success")), b(d.get("cached")),
          d.get("sha256"), d.get("file_type"), d.get("content_type"), d.get("size"),
          d.get("duration_ms")) for d in e.get("downloads") or []],
    )
    cur.executemany(
        "INSERT INTO credentials VALUES (?,?,?)",
        [(eid, c.get("username"), c.get("password")) for c in e.get("credentials") or []],
    )
    cur.executemany(
        "INSERT OR IGNORE INTO dropped_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [(eid, i, d.get("path"), d.get("via"), d.get("mode"), d.get("status"), b(d.get("success")),
          b(d.get("incomplete")), b(d.get("executable")), d.get("sha256"), d.get("file_type"), d.get("size"))
         for i, d in enumerate(e.get("dropped") or [])],
    )
    cur.executemany(
        "INSERT OR IGNORE INTO commands VALUES (?,?,?)",
        [(eid, i, c) for i, c in enumerate(e.get("commands") or [])],
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="JSONL files, globs or directories")
    ap.add_argument("--db", default="honeypot.sqlite", help="output SQLite file")
    args = ap.parse_args()

    files = resolve_files(args.inputs)
    if not files:
        print("no .jsonl files found", file=sys.stderr)
        return 1

    con = sqlite3.connect(args.db)
    con.execute("PRAGMA foreign_keys = ON")
    con.executescript(SCHEMA)
    cols = {r[1] for r in con.execute("PRAGMA table_info(events)")}
    if "signature" not in cols:
        con.execute("ALTER TABLE events ADD COLUMN signature TEXT")
    cur = con.cursor()
    n = bad = 0
    for ev, bad in iter_events(files):
        try:
            insert_event(cur, ev)
        except KeyError as exc:
            bad += 1
            print(f"skipping event without field {exc}", file=sys.stderr)
            continue
        n += 1
        if n % 5000 == 0:
            con.commit()
    con.commit()

    print(f"files: {len(files)}  events loaded: {n}  malformed lines: {bad}")
    for table in ("events", "event_techniques", "event_iocs", "downloads", "credentials", "commands", "dropped_files"):
        (c,) = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        print(f"  {table:18s} {c}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
