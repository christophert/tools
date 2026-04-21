#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import re
import sqlite3
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from tabulate import tabulate as _tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

UAC_FLAGS = {
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}

FILETIME_EPOCH_DELTA = 116444736000000000
FILETIME_NEVER = 9223372036854775807


# ---------------------------------------------------------------------------
# LDIF Parser
# ---------------------------------------------------------------------------

def _unwrap_ldif_lines(lines: list) -> list:
    result = []
    for line in lines:
        if line.startswith(" ") and result:
            result[-1] = result[-1] + line[1:]
        else:
            result.append(line)
    return result


def _decode_attr_value(raw: str, is_base64: bool):
    if not is_base64:
        return raw.strip()
    raw_bytes = base64.b64decode(raw.strip())
    try:
        return raw_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return raw_bytes


def parse_ldif(text: str) -> list:
    entries = []
    blocks = re.split(r"\n{2,}", text.strip())
    for block in blocks:
        lines = block.splitlines()
        lines = _unwrap_ldif_lines(lines)
        lines = [l for l in lines if not l.startswith("#")]
        if not lines:
            continue

        dn = None
        attrs = {}
        is_referral = False

        for line in lines:
            if not line.strip():
                continue
            if line.startswith("ref:"):
                is_referral = True
                continue
            if "::" in line:
                sep_idx = line.index("::")
                attr_name = line[:sep_idx].strip()
                raw_val = line[sep_idx + 2:].strip()
                value = _decode_attr_value(raw_val, True)
            elif ":" in line:
                sep_idx = line.index(":")
                attr_name = line[:sep_idx].strip()
                raw_val = line[sep_idx + 1:].strip()
                value = raw_val
            else:
                continue

            if attr_name.lower() == "dn":
                dn = value
            else:
                attrs.setdefault(attr_name, []).append(value)

        if dn is None or is_referral:
            continue

        entries.append({"dn": dn, "attrs": attrs})

    return entries


# ---------------------------------------------------------------------------
# Binary Decoders
# ---------------------------------------------------------------------------

def decode_sid(raw: bytes) -> str:
    if len(raw) < 8:
        raise ValueError(f"SID too short: {len(raw)} bytes")
    revision = raw[0]
    sub_count = raw[1]
    if len(raw) < 8 + sub_count * 4:
        raise ValueError(f"SID data too short for {sub_count} sub-authorities")
    authority = int.from_bytes(raw[2:8], "big")
    subs = [struct.unpack_from("<I", raw, 8 + i * 4)[0] for i in range(sub_count)]
    return "S-{}-{}-{}".format(revision, authority, "-".join(str(s) for s in subs))


def decode_guid(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw))


def decode_filetime(value: str) -> str | None:
    v = int(value)
    if v == 0 or v == FILETIME_NEVER:
        return None
    unix_ts = (v - FILETIME_EPOCH_DELTA) / 10_000_000
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()


def parse_uac(uac_value: str) -> dict:
    flags = int(uac_value)
    result = {name: bool(flags & mask) for mask, name in UAC_FLAGS.items()}
    result["enabled"] = not bool(flags & 0x0002)
    return result


# ---------------------------------------------------------------------------
# SQLite Layer
# ---------------------------------------------------------------------------

def get_db_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS entries (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dn           TEXT NOT NULL UNIQUE,
            object_class TEXT,
            attrs_json   TEXT NOT NULL,
            inserted_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_entries_dn ON entries(dn);
        CREATE INDEX IF NOT EXISTS idx_entries_object_class ON entries(object_class);

        CREATE TABLE IF NOT EXISTS attr_index (
            entry_id   INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
            attr_name  TEXT NOT NULL,
            attr_value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_attr_name ON attr_index(attr_name);
        CREATE INDEX IF NOT EXISTS idx_attr_name_value ON attr_index(attr_name, attr_value);

        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()


def _serialize_attrs(attrs: dict) -> dict:
    serialized = {}
    for k, vals in attrs.items():
        serialized[k] = [
            "hex:" + v.hex() if isinstance(v, bytes) else v
            for v in vals
        ]
    return serialized


def insert_entry(conn: sqlite3.Connection, entry: dict) -> int:
    dn = entry["dn"]
    attrs = entry.get("attrs", {})
    object_class = ",".join(attrs.get("objectClass", []))
    attrs_json = json.dumps(_serialize_attrs(attrs))

    cur = conn.execute(
        "INSERT OR REPLACE INTO entries (dn, object_class, attrs_json) VALUES (?, ?, ?)",
        (dn, object_class, attrs_json),
    )
    entry_id = cur.lastrowid
    conn.execute("DELETE FROM attr_index WHERE entry_id = ?", (entry_id,))

    rows = []
    for attr_name, vals in attrs.items():
        lower_name = attr_name.lower()
        for v in vals:
            if isinstance(v, bytes):
                str_val = "hex:" + v.hex()
            else:
                str_val = str(v).lower()
            rows.append((entry_id, lower_name, str_val))

    conn.executemany("INSERT INTO attr_index (entry_id, attr_name, attr_value) VALUES (?, ?, ?)", rows)
    conn.commit()
    return entry_id


def insert_entries_batch(conn: sqlite3.Connection, entries: list) -> int:
    count = 0
    for i, entry in enumerate(entries):
        insert_entry(conn, entry)
        count += 1
        if (i + 1) % 1000 == 0:
            log.info("Inserted %d entries...", i + 1)
    return count


def store_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
    conn.commit()


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


# ---------------------------------------------------------------------------
# Query Layer
# ---------------------------------------------------------------------------

def build_query_sql(object_class, attr_filter, search, dn) -> tuple:
    if dn is not None:
        return "SELECT * FROM entries WHERE dn = ?", [dn]

    conditions = []
    params = []
    joins = ""

    if object_class:
        conditions.append("e.object_class LIKE ?")
        params.append(f"%{object_class}%")

    if attr_filter:
        if "=" in attr_filter:
            attr_name, attr_val = attr_filter.split("=", 1)
            attr_val_sql = attr_val.replace("*", "%")
            joins = " JOIN attr_index ai ON ai.entry_id = e.id"
            conditions.append("ai.attr_name = ?")
            params.append(attr_name.lower())
            conditions.append("ai.attr_value LIKE ?")
            params.append(attr_val_sql.lower())

    if search:
        conditions.append("e.attrs_json LIKE ?")
        params.append(f"%{search}%")

    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    sql = f"SELECT DISTINCT e.* FROM entries e{joins}{where}"
    return sql, params


def format_entry_detail(row: sqlite3.Row) -> str:
    attrs = json.loads(row["attrs_json"])
    lines = [f"dn: {row['dn']}"]
    for attr, vals in attrs.items():
        for v in vals:
            lines.append(f"  {attr}: {v}")
    return "\n".join(lines)


def _simple_table(headers: list, rows: list) -> str:
    widths = [max(len(str(headers[i])), max((len(str(r[i])) for r in rows), default=0)) for i in range(len(headers))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), "-" * sum(widths + [2] * (len(widths) - 1))]
    for row in rows:
        lines.append(fmt.format(*[str(v)[:widths[i]] for i, v in enumerate(row)]))
    return "\n".join(lines)


def format_table(rows: list, extra_attrs: list | None = None) -> str:
    headers = ["dn", "object_class"]
    table_rows = []
    for row in rows:
        r = [row["dn"], row["object_class"] or ""]
        if extra_attrs:
            attrs = json.loads(row["attrs_json"])
            for a in extra_attrs:
                vals = attrs.get(a, attrs.get(a.lower(), []))
                r.append(", ".join(str(v) for v in vals) if vals else "")
            headers_full = headers + extra_attrs
        else:
            headers_full = headers
        table_rows.append(r)
    if HAS_TABULATE:
        return _tabulate(table_rows, headers=headers_full, tablefmt="simple")
    return _simple_table(headers_full, table_rows)


# ---------------------------------------------------------------------------
# BloodHound Builders
# ---------------------------------------------------------------------------

def extract_domain_from_dn(dn: str) -> str:
    parts = re.findall(r"DC=([^,]+)", dn, re.IGNORECASE)
    return ".".join(p.upper() for p in parts)


def _get_sid_from_entry(entry: dict) -> str | None:
    raw_vals = entry.get("attrs", {}).get("objectSid", [])
    if not raw_vals:
        return None
    v = raw_vals[0]
    if isinstance(v, bytes):
        try:
            return decode_sid(v)
        except (ValueError, struct.error):
            return None
    return None


def build_bh_user(entry: dict, domain_fqdn: str, domain_sid: str) -> dict | None:
    attrs = entry.get("attrs", {})
    sid = _get_sid_from_entry(entry)
    if not sid:
        return None

    sam = (attrs.get("sAMAccountName", [""]))[0]
    name = f"{sam.upper()}@{domain_fqdn}"

    uac_vals = attrs.get("userAccountControl", [])
    uac = parse_uac(uac_vals[0]) if uac_vals else {"enabled": True, "DONT_EXPIRE_PASSWORD": False,
                                                     "TRUSTED_FOR_DELEGATION": False, "DONT_REQ_PREAUTH": False,
                                                     "PASSWD_NOTREQD": False, "SMARTCARD_REQUIRED": False}

    spns = attrs.get("servicePrincipalName", [])
    primary_gid = (attrs.get("primaryGroupID", ["513"]))[0]

    props = {
        "name": name,
        "domain": domain_fqdn,
        "domainsid": domain_sid,
        "distinguishedname": entry["dn"].upper(),
        "samaccountname": sam,
        "email": (attrs.get("mail", [None]))[0],
        "title": (attrs.get("title", [None]))[0],
        "description": (attrs.get("description", [None]))[0],
        "enabled": uac.get("enabled", True),
        "lastlogon": _filetime_to_unix(attrs.get("lastLogon", ["0"])[0]),
        "lastlogontimestamp": _filetime_to_unix(attrs.get("lastLogonTimestamp", ["0"])[0]),
        "pwdlastset": _filetime_to_unix(attrs.get("pwdLastSet", ["0"])[0]),
        "dontreqpreauth": uac.get("DONT_REQ_PREAUTH", False),
        "passwordnotreqd": uac.get("PASSWD_NOTREQD", False),
        "sensitive": False,
        "serviceprincipalnames": spns,
        "hasspn": bool(spns),
        "displayname": (attrs.get("displayName", [None]))[0],
        "pwdneverexpires": uac.get("DONT_EXPIRE_PASSWORD", False),
        "admincount": bool(attrs.get("adminCount", ["0"])[0] == "1"),
        "unconstraineddelegation": uac.get("TRUSTED_FOR_DELEGATION", False),
        "objectid": sid,
        "whencreated": _filetime_to_unix(attrs.get("whenCreated", ["0"])[0]),
    }

    return {
        "Properties": props,
        "ObjectIdentifier": sid,
        "PrimaryGroupSID": f"{domain_sid}-{primary_gid}",
        "SPNTargets": [],
        "HasSIDHistory": [],
        "IsACLProtected": False,
        "Aces": [],
    }


def build_bh_group(entry: dict, domain_fqdn: str, domain_sid: str,
                   dn_to_sid: dict, dn_to_type: dict) -> dict | None:
    attrs = entry.get("attrs", {})
    sid = _get_sid_from_entry(entry)
    if not sid:
        return None

    sam = (attrs.get("sAMAccountName", [""]))[0]
    name = f"{sam.upper()}@{domain_fqdn}"
    member_dns = attrs.get("member", [])
    members = []
    for mdn in member_dns:
        mdn_lower = mdn.lower()
        msid = dn_to_sid.get(mdn_lower)
        if not msid:
            continue
        mtype = dn_to_type.get(mdn_lower, "Base")
        members.append({"MemberId": msid, "MemberType": mtype})

    props = {
        "name": name,
        "domain": domain_fqdn,
        "domainsid": domain_sid,
        "distinguishedname": entry["dn"].upper(),
        "samaccountname": sam,
        "description": (attrs.get("description", [None]))[0],
        "admincount": bool(attrs.get("adminCount", ["0"])[0] == "1"),
        "objectid": sid,
    }

    return {
        "Properties": props,
        "ObjectIdentifier": sid,
        "Members": members,
        "IsACLProtected": False,
        "Aces": [],
    }


def build_bh_computer(entry: dict, domain_fqdn: str, domain_sid: str) -> dict | None:
    attrs = entry.get("attrs", {})
    sid = _get_sid_from_entry(entry)
    if not sid:
        return None

    sam = (attrs.get("sAMAccountName", [""]))[0].rstrip("$")
    dns_name = (attrs.get("dNSHostName", [None]))[0]
    name = (dns_name or f"{sam}.{domain_fqdn}").upper()

    uac_vals = attrs.get("userAccountControl", [])
    uac = parse_uac(uac_vals[0]) if uac_vals else {}

    props = {
        "name": name,
        "domain": domain_fqdn,
        "domainsid": domain_sid,
        "distinguishedname": entry["dn"].upper(),
        "samaccountname": sam,
        "dnshostname": dns_name,
        "operatingsystem": (attrs.get("operatingSystem", [None]))[0],
        "operatingsystemversion": (attrs.get("operatingSystemVersion", [None]))[0],
        "enabled": uac.get("enabled", True),
        "unconstraineddelegation": uac.get("TRUSTED_FOR_DELEGATION", False),
        "objectid": sid,
    }

    return {
        "Properties": props,
        "ObjectIdentifier": sid,
        "IsACLProtected": False,
        "Aces": [],
    }


def build_bh_domain(entry: dict) -> dict | None:
    attrs = entry.get("attrs", {})
    sid = _get_sid_from_entry(entry)
    if not sid:
        return None

    fqdn = extract_domain_from_dn(entry["dn"])
    props = {
        "name": fqdn,
        "domain": fqdn,
        "distinguishedname": entry["dn"].upper(),
        "objectid": sid,
        "functionallevel": (attrs.get("msDS-Behavior-Version", [None]))[0],
    }

    return {
        "Properties": props,
        "ObjectIdentifier": sid,
        "IsACLProtected": False,
        "Aces": [],
    }


def build_bh_ou(entry: dict, domain_fqdn: str) -> dict | None:
    attrs = entry.get("attrs", {})
    guid_vals = attrs.get("objectGUID", [])
    if not guid_vals:
        return None
    raw = guid_vals[0]
    if isinstance(raw, bytes):
        try:
            guid = decode_guid(raw)
        except (ValueError, AttributeError):
            return None
    else:
        guid = raw

    name = (attrs.get("name", [""]))[0]
    props = {
        "name": f"{name.upper()}@{domain_fqdn}",
        "domain": domain_fqdn,
        "distinguishedname": entry["dn"].upper(),
        "description": (attrs.get("description", [None]))[0],
        "objectid": guid,
    }

    return {
        "Properties": props,
        "ObjectIdentifier": guid,
        "IsACLProtected": False,
        "Aces": [],
    }


def _filetime_to_unix(value: str) -> int | None:
    try:
        v = int(value)
    except (ValueError, TypeError):
        return None
    if v == 0 or v == FILETIME_NEVER:
        return None
    return int((v - FILETIME_EPOCH_DELTA) / 10_000_000)


def build_dn_to_sid_map(conn: sqlite3.Connection) -> dict:
    mapping = {}
    rows = conn.execute(
        """
        SELECT e.dn, ai.attr_value
        FROM entries e
        JOIN attr_index ai ON ai.entry_id = e.id
        WHERE ai.attr_name = 'objectsid'
        """
    ).fetchall()
    for row in rows:
        hex_val = row["attr_value"]
        if hex_val.startswith("hex:"):
            try:
                raw = bytes.fromhex(hex_val[4:])
                sid = decode_sid(raw)
                mapping[row["dn"].lower()] = sid
            except (ValueError, struct.error):
                pass
    return mapping


def build_dn_to_type_map(conn: sqlite3.Connection) -> dict:
    mapping = {}
    rows = conn.execute("SELECT dn, object_class FROM entries").fetchall()
    for row in rows:
        classes = (row["object_class"] or "").lower().split(",")
        if "computer" in classes:
            t = "Computer"
        elif "group" in classes:
            t = "Group"
        elif "user" in classes:
            t = "User"
        else:
            t = "Base"
        mapping[row["dn"].lower()] = t
    return mapping


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_parse(args):
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"File not found: {input_path}")
        sys.exit(1)

    text = input_path.read_text(encoding="utf-8", errors="replace")
    log.info("Parsing LDIF...")
    entries = parse_ldif(text)
    log.info("Found %d entries", len(entries))

    if args.skip_deleted:
        entries = [e for e in entries if "CN=Deleted Objects" not in e["dn"]]
        log.info("%d entries after filtering tombstones", len(entries))

    conn = get_db_connection(args.db)
    init_db(conn)

    if args.no_index:
        for entry in entries:
            dn = entry["dn"]
            attrs = entry.get("attrs", {})
            object_class = ",".join(attrs.get("objectClass", []))
            attrs_json = json.dumps(_serialize_attrs(attrs))
            conn.execute(
                "INSERT OR REPLACE INTO entries (dn, object_class, attrs_json) VALUES (?, ?, ?)",
                (dn, object_class, attrs_json),
            )
        conn.commit()
    else:
        insert_entries_batch(conn, entries)

    # detect domain and store in meta
    for entry in entries:
        classes = entry.get("attrs", {}).get("objectClass", [])
        if "domain" in [c.lower() for c in classes]:
            fqdn = extract_domain_from_dn(entry["dn"])
            store_meta(conn, "domain_fqdn", fqdn)
            store_meta(conn, "root_dn", entry["dn"])
            sid = _get_sid_from_entry(entry)
            if sid:
                store_meta(conn, "domain_sid", sid)
            break

    log.info("Stored %d entries in %s", len(entries), args.db)


def cmd_export_bh(args):
    conn = get_db_connection(args.db)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    domain_fqdn = args.domain or get_meta(conn, "domain_fqdn") or "UNKNOWN.DOMAIN"
    domain_sid = get_meta(conn, "domain_sid") or ""

    log.info("Domain: %s  SID: %s", domain_fqdn, domain_sid)

    dn_to_sid = build_dn_to_sid_map(conn)
    dn_to_type = build_dn_to_type_map(conn)

    all_rows = conn.execute("SELECT dn, object_class, attrs_json FROM entries").fetchall()

    buckets = {"users": [], "groups": [], "computers": [], "domains": [], "ous": []}

    for row in all_rows:
        classes = (row["object_class"] or "").lower().split(",")
        attrs_raw = json.loads(row["attrs_json"])
        attrs = {}
        for k, vals in attrs_raw.items():
            decoded = []
            for v in vals:
                if isinstance(v, str) and v.startswith("hex:"):
                    decoded.append(bytes.fromhex(v[4:]))
                else:
                    decoded.append(v)
            attrs[k] = decoded

        entry = {"dn": row["dn"], "attrs": attrs}

        if "computer" in classes:
            node = build_bh_computer(entry, domain_fqdn, domain_sid)
            if node:
                buckets["computers"].append(node)
        elif "group" in classes:
            node = build_bh_group(entry, domain_fqdn, domain_sid, dn_to_sid, dn_to_type)
            if node:
                buckets["groups"].append(node)
        elif "user" in classes:
            node = build_bh_user(entry, domain_fqdn, domain_sid)
            if node:
                buckets["users"].append(node)
        elif "domain" in classes:
            node = build_bh_domain(entry)
            if node:
                buckets["domains"].append(node)
        elif "organizationalunit" in classes:
            node = build_bh_ou(entry, domain_fqdn)
            if node:
                buckets["ous"].append(node)

    type_map = {
        "users": "users",
        "groups": "groups",
        "computers": "computers",
        "domains": "domains",
        "ous": "ous",
    }

    for key, data in buckets.items():
        out_file = output_dir / f"{key}.json"
        payload = {
            "data": data,
            "meta": {
                "methods": 0,
                "type": type_map[key],
                "count": len(data),
                "version": 4,
            },
        }
        out_file.write_text(json.dumps(payload, indent=2))
        log.info("Wrote %d %s to %s", len(data), key, out_file)


def cmd_query(args):
    conn = get_db_connection(args.db)

    sql, params = build_query_sql(
        object_class=args.object_class,
        attr_filter=args.attr,
        search=args.search,
        dn=args.dn,
    )

    if args.search:
        log.info("Warning: --search performs a full table scan and may be slow on large databases")

    limit = getattr(args, "limit", 50)
    if args.dn is None:
        sql += f" LIMIT {int(limit)}"

    rows = conn.execute(sql, params).fetchall()

    if not rows:
        print("No results.")
        return

    output_fmt = getattr(args, "output_fmt", "table")
    extra_attrs = [a.strip() for a in args.attrs.split(",")] if getattr(args, "attrs", None) else None

    if args.dn and len(rows) == 1:
        print(format_entry_detail(rows[0]))
        return

    if output_fmt == "json":
        out = []
        for row in rows:
            attrs = json.loads(row["attrs_json"])
            out.append({"dn": row["dn"], "object_class": row["object_class"], "attrs": attrs})
        print(json.dumps(out, indent=2))
    else:
        print(format_table(rows, extra_attrs))
        print(f"\n{len(rows)} result(s)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="parse_ldap.py",
        description="Parse ldapsearch LDIF output to SQLite and BloodHound JSON",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser("parse", help="Read LDIF file into SQLite")
    p_parse.add_argument("-i", "--input", required=True, metavar="LDIF_FILE")
    p_parse.add_argument("-d", "--db", default="ldap.db", metavar="DB_FILE")
    p_parse.add_argument("--no-index", dest="no_index", action="store_true")
    p_parse.add_argument("--skip-deleted", dest="skip_deleted", action="store_true")

    p_bh = sub.add_parser("export-bh", help="Export SQLite to BloodHound JSON")
    p_bh.add_argument("-d", "--db", default="ldap.db", metavar="DB_FILE")
    p_bh.add_argument("-o", "--output", default=".", metavar="OUTPUT_DIR")
    p_bh.add_argument("--domain", default=None, metavar="FQDN")

    p_query = sub.add_parser("query", help="Query the SQLite database")
    p_query.add_argument("-d", "--db", default="ldap.db", metavar="DB_FILE")
    p_query.add_argument("--class", dest="object_class", metavar="CLASS")
    p_query.add_argument("--attr", metavar="NAME=VALUE")
    p_query.add_argument("--search", metavar="TEXT")
    p_query.add_argument("--dn", metavar="DN")
    p_query.add_argument("--output", dest="output_fmt", choices=["table", "json"], default="table")
    p_query.add_argument("--attrs", metavar="ATTR1,ATTR2", default=None)
    p_query.add_argument("--limit", type=int, default=50)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    dispatch = {"parse": cmd_parse, "export-bh": cmd_export_bh, "query": cmd_query}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
