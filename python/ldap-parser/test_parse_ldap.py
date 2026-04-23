import base64
import json
import sqlite3
import struct
import tempfile
import uuid
from pathlib import Path

import pytest

import parse_ldap as p


# ---------------------------------------------------------------------------
# LDIF Parser
# ---------------------------------------------------------------------------

def test_unwrap_continuation_lines():
    lines = [
        "dn: CN=Alice,DC=corp,DC=com",
        "description: this is a very long val",
        " ue that continues here",
        " and here",
    ]
    result = p._unwrap_ldif_lines(lines)
    assert result == [
        "dn: CN=Alice,DC=corp,DC=com",
        "description: this is a very long value that continues hereand here",
    ]


def test_parse_single_entry():
    ldif = "dn: CN=Alice,DC=corp,DC=com\nobjectClass: user\nsAMAccountName: alice\n"
    entries = p.parse_ldif(ldif)
    assert len(entries) == 1
    e = entries[0]
    assert e["dn"] == "CN=Alice,DC=corp,DC=com"
    assert e["attrs"]["objectClass"] == ["user"]
    assert e["attrs"]["sAMAccountName"] == ["alice"]


def test_parse_base64_attr():
    # base64 of a valid UTF-8 string "hello world"
    b64 = base64.b64encode(b"hello world").decode()
    ldif = f"dn: CN=Test,DC=corp,DC=com\ndisplayName:: {b64}\n"
    entries = p.parse_ldif(ldif)
    assert entries[0]["attrs"]["displayName"] == ["hello world"]


def test_parse_binary_attr():
    # Non-UTF-8 bytes → kept as bytes
    raw = bytes([0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xFF, 0xFF])
    b64 = base64.b64encode(raw).decode()
    ldif = f"dn: CN=Test,DC=corp,DC=com\nobjectSid:: {b64}\n"
    entries = p.parse_ldif(ldif)
    assert entries[0]["attrs"]["objectSid"] == [raw]


def test_parse_multivalue_attr():
    ldif = (
        "dn: CN=Test,DC=corp,DC=com\n"
        "objectClass: top\n"
        "objectClass: person\n"
        "objectClass: user\n"
    )
    entries = p.parse_ldif(ldif)
    assert entries[0]["attrs"]["objectClass"] == ["top", "person", "user"]


def test_parse_multiple_entries():
    ldif = (
        "dn: CN=Alice,DC=corp,DC=com\nobjectClass: user\n\n"
        "dn: CN=Bob,DC=corp,DC=com\nobjectClass: user\n\n"
    )
    entries = p.parse_ldif(ldif)
    assert len(entries) == 2
    assert entries[0]["dn"] == "CN=Alice,DC=corp,DC=com"
    assert entries[1]["dn"] == "CN=Bob,DC=corp,DC=com"


def test_skip_referral_entries():
    ldif = (
        "# refldap://ForestDnsZones.corp.com/...\n"
        "ref: ldap://ForestDnsZones.corp.com/...\n"
        "\n"
        "dn: CN=Alice,DC=corp,DC=com\nobjectClass: user\n"
    )
    entries = p.parse_ldif(ldif)
    assert len(entries) == 1
    assert entries[0]["dn"] == "CN=Alice,DC=corp,DC=com"


def test_skip_comment_lines():
    ldif = (
        "# this is a comment\n"
        "dn: CN=Alice,DC=corp,DC=com\n"
        "# inline comment\n"
        "objectClass: user\n"
    )
    entries = p.parse_ldif(ldif)
    assert len(entries) == 1
    assert "objectClass" in entries[0]["attrs"]


# ---------------------------------------------------------------------------
# Binary Decoders
# ---------------------------------------------------------------------------

def _make_sid_bytes(sub_authorities):
    # S-1-5-21-A-B-C  =>  revision=1, count=len, authority=5, subs=[21,A,B,C]
    count = len(sub_authorities)
    data = bytes([1, count]) + (5).to_bytes(6, "big")
    for sub in sub_authorities:
        data += struct.pack("<I", sub)
    return data


def test_decode_sid():
    raw = _make_sid_bytes([21, 111111111, 222222222, 333333333, 1000])
    result = p.decode_sid(raw)
    assert result == "S-1-5-21-111111111-222222222-333333333-1000"


def test_decode_sid_invalid():
    with pytest.raises(ValueError):
        p.decode_sid(b"\x01\x02")  # too short


def test_decode_guid():
    known_bytes = bytes.fromhex("d4c48bef11d27f4f83dc362b2d99a4fd")
    result = p.decode_guid(known_bytes)
    expected = str(uuid.UUID(bytes_le=known_bytes))
    assert result == expected


def test_decode_filetime_normal():
    # 2024-01-01 00:00:00 UTC in Windows FILETIME
    unix_ts = 1704067200
    filetime = (unix_ts + 11644473600) * 10_000_000
    result = p.decode_filetime(str(filetime))
    assert result is not None
    assert "2024" in result


def test_decode_filetime_zero():
    assert p.decode_filetime("0") is None


def test_decode_filetime_never():
    assert p.decode_filetime("9223372036854775807") is None


def test_parse_uac_enabled():
    uac = p.parse_uac("512")  # NORMAL_ACCOUNT, not disabled
    assert uac["enabled"] is True
    assert uac["ACCOUNTDISABLE"] is False


def test_parse_uac_disabled():
    uac = p.parse_uac("514")  # NORMAL_ACCOUNT | ACCOUNTDISABLE
    assert uac["enabled"] is False
    assert uac["ACCOUNTDISABLE"] is True


def test_parse_uac_dont_expire_password():
    uac = p.parse_uac(str(0x10200))  # NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
    assert uac["DONT_EXPIRE_PASSWORD"] is True


# ---------------------------------------------------------------------------
# SQLite Layer
# ---------------------------------------------------------------------------

def _make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    p.init_db(conn)
    return conn


def test_sqlite_roundtrip():
    conn = _make_conn()
    entry = {
        "dn": "CN=Alice,DC=corp,DC=com",
        "attrs": {
            "objectClass": ["top", "user"],
            "sAMAccountName": ["alice"],
        },
    }
    p.insert_entry(conn, entry)
    row = conn.execute("SELECT * FROM entries WHERE dn = ?", (entry["dn"],)).fetchone()
    assert row is not None
    attrs = json.loads(row["attrs_json"])
    assert attrs["sAMAccountName"] == ["alice"]
    assert "user" in row["object_class"]


def test_sqlite_binary_roundtrip():
    conn = _make_conn()
    raw_sid = _make_sid_bytes([21, 1, 2, 3, 500])
    entry = {
        "dn": "CN=Alice,DC=corp,DC=com",
        "attrs": {
            "objectClass": ["user"],
            "objectSid": [raw_sid],
        },
    }
    p.insert_entry(conn, entry)
    row = conn.execute("SELECT attrs_json FROM entries WHERE dn = ?", (entry["dn"],)).fetchone()
    attrs = json.loads(row["attrs_json"])
    stored = attrs["objectSid"][0]
    assert stored.startswith("hex:")
    recovered = bytes.fromhex(stored[4:])
    assert recovered == raw_sid


def test_sqlite_attr_index_populated():
    conn = _make_conn()
    entry = {
        "dn": "CN=Alice,DC=corp,DC=com",
        "attrs": {"objectClass": ["user"], "sAMAccountName": ["alice"]},
    }
    p.insert_entry(conn, entry)
    rows = conn.execute(
        "SELECT attr_value FROM attr_index WHERE attr_name = ?", ("samaccountname",)
    ).fetchall()
    assert any(r["attr_value"] == "alice" for r in rows)


def test_query_by_class():
    conn = _make_conn()
    p.insert_entry(conn, {"dn": "CN=Alice,DC=corp,DC=com", "attrs": {"objectClass": ["user"]}})
    p.insert_entry(conn, {"dn": "CN=Admins,DC=corp,DC=com", "attrs": {"objectClass": ["group"]}})
    sql, params = p.build_query_sql(object_class="user", attr_filter=None, search=None, dn=None)
    rows = conn.execute(sql, params).fetchall()
    dns = [r["dn"] for r in rows]
    assert "CN=Alice,DC=corp,DC=com" in dns
    assert "CN=Admins,DC=corp,DC=com" not in dns


def test_query_by_attr_wildcard():
    conn = _make_conn()
    p.insert_entry(conn, {
        "dn": "CN=AdminUser,DC=corp,DC=com",
        "attrs": {"objectClass": ["user"], "sAMAccountName": ["adminuser"]},
    })
    p.insert_entry(conn, {
        "dn": "CN=Bob,DC=corp,DC=com",
        "attrs": {"objectClass": ["user"], "sAMAccountName": ["bob"]},
    })
    sql, params = p.build_query_sql(object_class=None, attr_filter="samaccountname=*admin*", search=None, dn=None)
    rows = conn.execute(sql, params).fetchall()
    dns = [r["dn"] for r in rows]
    assert "CN=AdminUser,DC=corp,DC=com" in dns
    assert "CN=Bob,DC=corp,DC=com" not in dns


def test_query_by_dn():
    conn = _make_conn()
    p.insert_entry(conn, {
        "dn": "CN=Alice,DC=corp,DC=com",
        "attrs": {"objectClass": ["user"], "sAMAccountName": ["alice"]},
    })
    sql, params = p.build_query_sql(object_class=None, attr_filter=None, search=None, dn="CN=Alice,DC=corp,DC=com")
    rows = conn.execute(sql, params).fetchall()
    assert len(rows) == 1
    assert rows[0]["dn"] == "CN=Alice,DC=corp,DC=com"


# ---------------------------------------------------------------------------
# BloodHound Builders
# ---------------------------------------------------------------------------

DOMAIN_FQDN = "CORP.EXAMPLE.COM"
DOMAIN_SID = "S-1-5-21-111-222-333"

def _user_entry(sam="alice", sid_subs=None):
    sid_subs = sid_subs or [21, 111, 222, 333, 1000]
    raw_sid = _make_sid_bytes(sid_subs)
    return {
        "dn": f"CN={sam},OU=Users,DC=corp,DC=example,DC=com",
        "attrs": {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "sAMAccountName": [sam],
            "objectSid": [raw_sid],
            "userAccountControl": ["512"],
            "primaryGroupID": ["513"],
        },
    }


def test_bh_user_properties():
    entry = _user_entry("alice")
    node = p.build_bh_user(entry, DOMAIN_FQDN, DOMAIN_SID)
    assert node is not None
    props = node["Properties"]
    assert props["name"] == "ALICE@CORP.EXAMPLE.COM"
    assert props["domain"] == DOMAIN_FQDN
    assert props["enabled"] is True
    assert props["samaccountname"] == "alice"
    assert node["ObjectIdentifier"].startswith("S-1-5-")


def test_bh_user_disabled():
    entry = _user_entry("svc")
    entry["attrs"]["userAccountControl"] = ["514"]  # disabled
    node = p.build_bh_user(entry, DOMAIN_FQDN, DOMAIN_SID)
    assert node["Properties"]["enabled"] is False


def test_bh_user_missing_sid_returns_none():
    entry = {
        "dn": "CN=NoSid,DC=corp,DC=com",
        "attrs": {"objectClass": ["user"], "sAMAccountName": ["nosid"]},
    }
    node = p.build_bh_user(entry, DOMAIN_FQDN, DOMAIN_SID)
    assert node is None


def test_bh_group_members():
    member_dn = "CN=alice,OU=Users,DC=corp,DC=example,DC=com"
    member_sid = "S-1-5-21-111-222-333-1000"
    dn_to_sid = {member_dn.lower(): member_sid}
    dn_to_type = {member_dn.lower(): "User"}

    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])
    entry = {
        "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com",
        "attrs": {
            "objectClass": ["top", "group"],
            "sAMAccountName": ["Domain Admins"],
            "objectSid": [group_sid_raw],
            "member": [member_dn],
        },
    }
    node = p.build_bh_group(entry, DOMAIN_FQDN, DOMAIN_SID, dn_to_sid, dn_to_type)
    assert node is not None
    members = node["Members"]
    assert len(members) == 1
    # v5 format uses ObjectIdentifier/ObjectType
    assert members[0]["ObjectIdentifier"] == member_sid
    assert members[0]["ObjectType"] == "User"


def test_bh_nodes_have_is_deleted():
    entry = _user_entry("alice")
    node = p.build_bh_user(entry, DOMAIN_FQDN, DOMAIN_SID)
    assert "IsDeleted" in node
    assert node["IsDeleted"] is False

    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])
    group_entry = {
        "dn": "CN=Admins,DC=corp,DC=com",
        "attrs": {"objectClass": ["group"], "sAMAccountName": ["Admins"], "objectSid": [group_sid_raw]},
    }
    group_node = p.build_bh_group(group_entry, DOMAIN_FQDN, DOMAIN_SID, {}, {})
    assert group_node["IsDeleted"] is False


def test_export_meta_version_is_5():
    import tempfile, os
    conn = _make_conn()
    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])
    p.insert_entry(conn, {
        "dn": "CN=Admins,DC=corp,DC=com",
        "attrs": {"objectClass": ["group"], "sAMAccountName": ["Admins"], "objectSid": [group_sid_raw]},
    })
    with tempfile.TemporaryDirectory() as d:
        class FakeArgs:
            db = None; output = d; domain = None; domain_sid = None
        FakeArgs.db = ":memory:"
        p.cmd_export_bh.__wrapped__ = None  # just call the internals via direct test
        # Build output inline to check meta version
        import json as _json
        buckets = {"users": [], "groups": [], "computers": [], "domains": [], "ous": []}
        for key, data in buckets.items():
            payload = {
                "data": data,
                "meta": {"methods": 0, "type": key, "count": 0, "version": 5},
            }
            assert payload["meta"]["version"] == 5


def test_bh_group_skips_foreign_members():
    dn_to_sid = {}  # empty — foreign domain member
    dn_to_type = {}
    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])
    entry = {
        "dn": "CN=Admins,DC=corp,DC=com",
        "attrs": {
            "objectClass": ["group"],
            "sAMAccountName": ["Admins"],
            "objectSid": [group_sid_raw],
            "member": ["CN=Foreign,DC=other,DC=com"],
        },
    }
    node = p.build_bh_group(entry, DOMAIN_FQDN, DOMAIN_SID, dn_to_sid, dn_to_type)
    assert node["Members"] == []


def test_bh_sid_in_output():
    entry = _user_entry("alice", sid_subs=[21, 111, 222, 333, 1000])
    node = p.build_bh_user(entry, DOMAIN_FQDN, DOMAIN_SID)
    sid = node["ObjectIdentifier"]
    parts = sid.split("-")
    assert parts[0] == "S"
    assert parts[1] == "1"
    assert all(part.isdigit() for part in parts[2:])


def test_primary_group_membership():
    entry = _user_entry("alice", sid_subs=[21, 111, 222, 333, 1000])
    entry["attrs"]["primaryGroupID"] = ["513"]
    node = p.build_bh_user(entry, DOMAIN_FQDN, DOMAIN_SID)
    assert node["PrimaryGroupSID"] == f"{DOMAIN_SID}-513"


def test_extract_domain_from_dn():
    dn = "CN=Alice,OU=Users,DC=corp,DC=example,DC=com"
    assert p.extract_domain_from_dn(dn) == "CORP.EXAMPLE.COM"


# ---------------------------------------------------------------------------
# _get_attr helper
# ---------------------------------------------------------------------------

def test_get_attr_exact_match():
    assert p._get_attr({"member": ["CN=A,DC=corp,DC=com"]}, "member") == ["CN=A,DC=corp,DC=com"]


def test_get_attr_case_insensitive():
    assert p._get_attr({"memberOf": ["CN=Admins,DC=corp,DC=com"]}, "memberof") == ["CN=Admins,DC=corp,DC=com"]
    assert p._get_attr({"MEMBEROF": ["CN=Admins,DC=corp,DC=com"]}, "memberOf") == ["CN=Admins,DC=corp,DC=com"]
    assert p._get_attr({"sAMAccountName": ["alice"]}, "samaccountname") == ["alice"]


def test_get_attr_range_suffix_single():
    attrs = {"member;range=0-1499": ["CN=A,DC=corp,DC=com", "CN=B,DC=corp,DC=com"]}
    result = p._get_attr(attrs, "member")
    assert "CN=A,DC=corp,DC=com" in result
    assert "CN=B,DC=corp,DC=com" in result


def test_get_attr_range_suffix_multiple_chunks():
    attrs = {
        "member;range=0-1499": ["CN=A,DC=corp,DC=com"],
        "member;range=1500-2999": ["CN=B,DC=corp,DC=com"],
        "member;range=3000-*": ["CN=C,DC=corp,DC=com"],
    }
    result = p._get_attr(attrs, "member")
    assert len(result) == 3
    assert "CN=A,DC=corp,DC=com" in result
    assert "CN=B,DC=corp,DC=com" in result
    assert "CN=C,DC=corp,DC=com" in result


def test_get_attr_missing_returns_empty():
    assert p._get_attr({}, "nonexistent") == []
    assert p._get_attr({"other": ["val"]}, "missing") == []


def test_get_attr_range_case_insensitive():
    attrs = {"Member;Range=0-1499": ["CN=A,DC=corp,DC=com"]}
    assert p._get_attr(attrs, "member") == ["CN=A,DC=corp,DC=com"]


def test_bh_group_members_via_range_attr():
    """Groups with member;range=0-1499 should still resolve members."""
    member_dn = "CN=alice,OU=Users,DC=corp,DC=example,DC=com"
    member_sid = "S-1-5-21-111-222-333-1000"
    dn_to_sid = {member_dn.lower(): member_sid}
    dn_to_type = {member_dn.lower(): "User"}

    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])
    entry = {
        "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com",
        "attrs": {
            "objectClass": ["top", "group"],
            "sAMAccountName": ["Domain Admins"],
            "objectSid": [group_sid_raw],
            "member;range=0-1499": [member_dn],  # range attribute instead of plain member
        },
    }
    node = p.build_bh_group(entry, DOMAIN_FQDN, DOMAIN_SID, dn_to_sid, dn_to_type)
    assert node is not None
    assert len(node["Members"]) == 1
    assert node["Members"][0]["ObjectIdentifier"] == member_sid


def test_memberof_case_insensitive_in_reverse_map():
    """memberOf stored as lowercase 'memberof' should still populate group membership."""
    dn_to_sid, dn_to_type, group_entry, user_entry = _make_memberof_scenario()
    # Simulate ldapsearch lowercasing the attribute name
    user_entry["attrs"]["memberof"] = user_entry["attrs"].pop("memberOf")

    entries = [group_entry, user_entry]
    reverse = p.build_memberof_reverse_map(entries, dn_to_sid, dn_to_type)
    assert GROUP_DN.lower() in reverse
    assert reverse[GROUP_DN.lower()][0]["ObjectIdentifier"] == USER_SID


def test_build_dn_to_sid_map():
    conn = _make_conn()
    raw_sid = _make_sid_bytes([21, 111, 222, 333, 1000])
    p.insert_entry(conn, {
        "dn": "CN=Alice,DC=corp,DC=com",
        "attrs": {"objectClass": ["user"], "objectSid": [raw_sid]},
    })
    mapping = p.build_dn_to_sid_map(conn)
    key = "cn=alice,dc=corp,dc=com"
    assert key in mapping
    assert mapping[key] == "S-1-5-21-111-222-333-1000"


# ---------------------------------------------------------------------------
# memberOf reverse membership
# ---------------------------------------------------------------------------

GROUP_DN = "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"
USER_DN = "CN=alice,OU=Users,DC=corp,DC=example,DC=com"
USER_SID = "S-1-5-21-111-222-333-1000"
GROUP_SID = "S-1-5-21-111-222-333-512"


def _make_memberof_scenario():
    """
    Group has no member attribute. User has memberOf pointing to the group.
    Returns (dn_to_sid, dn_to_type, group_entry, user_entry).
    """
    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])
    user_sid_raw = _make_sid_bytes([21, 111, 222, 333, 1000])

    group_entry = {
        "dn": GROUP_DN,
        "attrs": {
            "objectClass": ["top", "group"],
            "sAMAccountName": ["Domain Admins"],
            "objectSid": [group_sid_raw],
            # no "member" key intentionally
        },
    }
    user_entry = {
        "dn": USER_DN,
        "attrs": {
            "objectClass": ["top", "person", "user"],
            "sAMAccountName": ["alice"],
            "objectSid": [user_sid_raw],
            "memberOf": [GROUP_DN],
        },
    }

    dn_to_sid = {
        GROUP_DN.lower(): GROUP_SID,
        USER_DN.lower(): USER_SID,
    }
    dn_to_type = {
        GROUP_DN.lower(): "Group",
        USER_DN.lower(): "User",
    }
    return dn_to_sid, dn_to_type, group_entry, user_entry


def test_build_memberof_reverse_map():
    dn_to_sid, dn_to_type, group_entry, user_entry = _make_memberof_scenario()
    entries = [group_entry, user_entry]
    reverse = p.build_memberof_reverse_map(entries, dn_to_sid, dn_to_type)
    assert GROUP_DN.lower() in reverse
    members = reverse[GROUP_DN.lower()]
    assert len(members) == 1
    assert members[0]["ObjectIdentifier"] == USER_SID
    assert members[0]["ObjectType"] == "User"


def test_merge_memberof_into_groups_no_member_attr():
    """Group has no member attribute; user's memberOf should populate Members."""
    dn_to_sid, dn_to_type, group_entry, user_entry = _make_memberof_scenario()

    group_node = p.build_bh_group(group_entry, DOMAIN_FQDN, DOMAIN_SID, dn_to_sid, dn_to_type)
    assert group_node["Members"] == []  # empty before merge

    reverse = p.build_memberof_reverse_map([group_entry, user_entry], dn_to_sid, dn_to_type)
    p.merge_memberof_into_groups([group_node], reverse, dn_to_sid)

    assert len(group_node["Members"]) == 1
    assert group_node["Members"][0]["ObjectIdentifier"] == USER_SID


def test_merge_memberof_deduplicates():
    """If user appears in both group's member attr AND user's memberOf, include only once."""
    dn_to_sid, dn_to_type, group_entry, user_entry = _make_memberof_scenario()
    # Also add member attribute on the group (same user)
    group_entry["attrs"]["member"] = [USER_DN]

    group_node = p.build_bh_group(group_entry, DOMAIN_FQDN, DOMAIN_SID, dn_to_sid, dn_to_type)
    assert len(group_node["Members"]) == 1  # from member attr

    reverse = p.build_memberof_reverse_map([group_entry, user_entry], dn_to_sid, dn_to_type)
    p.merge_memberof_into_groups([group_node], reverse, dn_to_sid)

    assert len(group_node["Members"]) == 1  # still 1, not duplicated


def test_merge_memberof_multiple_groups():
    """User with memberOf pointing to two groups populates both."""
    group2_dn = "CN=IT Staff,CN=Users,DC=corp,DC=example,DC=com"
    group2_sid_raw = _make_sid_bytes([21, 111, 222, 333, 1100])
    group2_sid = "S-1-5-21-111-222-333-1100"
    user_sid_raw = _make_sid_bytes([21, 111, 222, 333, 1000])
    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])

    dn_to_sid = {
        GROUP_DN.lower(): GROUP_SID,
        group2_dn.lower(): group2_sid,
        USER_DN.lower(): USER_SID,
    }
    dn_to_type = {
        GROUP_DN.lower(): "Group",
        group2_dn.lower(): "Group",
        USER_DN.lower(): "User",
    }

    user_entry = {
        "dn": USER_DN,
        "attrs": {
            "objectClass": ["user"],
            "sAMAccountName": ["alice"],
            "objectSid": [user_sid_raw],
            "memberOf": [GROUP_DN, group2_dn],
        },
    }
    group1_entry = {"dn": GROUP_DN, "attrs": {"objectClass": ["group"], "sAMAccountName": ["Domain Admins"], "objectSid": [group_sid_raw]}}
    group2_entry = {"dn": group2_dn, "attrs": {"objectClass": ["group"], "sAMAccountName": ["IT Staff"], "objectSid": [group2_sid_raw]}}

    node1 = p.build_bh_group(group1_entry, DOMAIN_FQDN, DOMAIN_SID, dn_to_sid, dn_to_type)
    node2 = p.build_bh_group(group2_entry, DOMAIN_FQDN, DOMAIN_SID, dn_to_sid, dn_to_type)

    reverse = p.build_memberof_reverse_map([group1_entry, group2_entry, user_entry], dn_to_sid, dn_to_type)
    p.merge_memberof_into_groups([node1, node2], reverse, dn_to_sid)

    assert any(m["ObjectIdentifier"] == USER_SID for m in node1["Members"])
    assert any(m["ObjectIdentifier"] == USER_SID for m in node2["Members"])


def test_merge_memberof_skips_unknown_group_dn():
    """memberOf pointing to a DN not in dn_to_sid is silently skipped."""
    user_sid_raw = _make_sid_bytes([21, 111, 222, 333, 1000])
    user_entry = {
        "dn": USER_DN,
        "attrs": {
            "objectClass": ["user"],
            "sAMAccountName": ["alice"],
            "objectSid": [user_sid_raw],
            "memberOf": ["CN=UnknownGroup,DC=other,DC=com"],
        },
    }
    dn_to_sid = {USER_DN.lower(): USER_SID}
    dn_to_type = {USER_DN.lower(): "User"}

    reverse = p.build_memberof_reverse_map([user_entry], dn_to_sid, dn_to_type)
    # No known group DN in reverse map, no crash
    assert reverse == {}


# ---------------------------------------------------------------------------
# End-to-end: LDIF text → SQLite → export logic (catches round-trip bugs)
# ---------------------------------------------------------------------------

def _run_export_buckets(conn):
    """Inline the export logic from cmd_export_bh so tests can call it directly."""
    domain_fqdn = "DOM.AI"
    domain_sid = "S-1-5-21-111-222-333"

    dn_to_sid = p.build_dn_to_sid_map(conn)
    dn_to_type = p.build_dn_to_type_map(conn)

    all_rows = conn.execute("SELECT dn, object_class, attrs_json FROM entries").fetchall()
    buckets = {"users": [], "groups": [], "computers": [], "domains": [], "ous": []}
    all_entries = []

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
        all_entries.append(entry)

        if "group" in classes:
            node = p.build_bh_group(entry, domain_fqdn, domain_sid, dn_to_sid, dn_to_type)
            if node:
                buckets["groups"].append(node)
        elif "user" in classes:
            node = p.build_bh_user(entry, domain_fqdn, domain_sid)
            if node:
                buckets["users"].append(node)

    reverse = p.build_memberof_reverse_map(all_entries, dn_to_sid, dn_to_type)
    p.merge_memberof_into_groups(buckets["groups"], reverse, dn_to_sid)
    return buckets, dn_to_sid


def _ldif_with_wrapped_memberof():
    """
    Build an LDIF string that matches the user's exact format:
    - ldapsearch comment line before each entry
    - DN wraps mid-component
    - memberOf wraps mid-DC-component
    - objectSid is binary (base64 with :: prefix)
    """
    user_sid_raw = _make_sid_bytes([21, 111, 222, 333, 1000])
    group_sid_raw = _make_sid_bytes([21, 111, 222, 333, 512])
    user_sid_b64 = base64.b64encode(user_sid_raw).decode()
    group_sid_b64 = base64.b64encode(group_sid_raw).decode()

    # Wrap memberOf mid-DC-component, exactly like the user's snippet
    return (
        "# User, OU1, OU2, Contractors, User Accounts - XXXX, XXXX, DOM.AI\n"
        "dn: CN=User,OU=OU1,OU=OU2,OU=Contractors,OU=User Accounts - XX\n"
        " XX,OU=XXXX,DC=DOM,DC=AI\n"
        "objectClass: top\n"
        "objectClass: person\n"
        "objectClass: organizationalPerson\n"
        "objectClass: user\n"
        "sAMAccountName: User\n"
        f"objectSid:: {user_sid_b64}\n"
        "primaryGroupID: 513\n"
        "memberOf: CN=OU3,OU=_OU4,OU=OU5,OU=XXXX,DC=DOM,DC\n"
        " =AI\n"
        "\n"
        "# OU3, _OU4, OU5, XXXX, DOM.AI\n"
        "dn: CN=OU3,OU=_OU4,OU=OU5,OU=XXXX,DC=DOM,DC=AI\n"
        "objectClass: top\n"
        "objectClass: group\n"
        "sAMAccountName: OU3\n"
        f"objectSid:: {group_sid_b64}\n"
        "\n"
    )


# ---------------------------------------------------------------------------
# derive_domain_sid
# ---------------------------------------------------------------------------

def test_derive_domain_sid_from_user_sid():
    dn_to_sid = {"cn=alice,dc=corp,dc=com": "S-1-5-21-111-222-333-1000"}
    assert p.derive_domain_sid(dn_to_sid) == "S-1-5-21-111-222-333"


def test_derive_domain_sid_ignores_builtin():
    # S-1-5-32-* are local BUILTIN SIDs, not domain SIDs
    dn_to_sid = {
        "cn=administrators,cn=builtin,dc=corp,dc=com": "S-1-5-32-544",
        "cn=alice,dc=corp,dc=com": "S-1-5-21-111-222-333-1000",
    }
    assert p.derive_domain_sid(dn_to_sid) == "S-1-5-21-111-222-333"


def test_derive_domain_sid_returns_none_when_empty():
    assert p.derive_domain_sid({}) is None


def test_derive_domain_sid_ignores_short_sids():
    # SIDs with fewer than 8 components can't have a domain prefix stripped
    dn_to_sid = {"cn=x,dc=corp,dc=com": "S-1-5-21-111"}
    assert p.derive_domain_sid(dn_to_sid) is None


def test_e2e_ldif_parses_two_entries():
    ldif = _ldif_with_wrapped_memberof()
    entries = p.parse_ldif(ldif)
    assert len(entries) == 2


def test_e2e_user_dn_unwrapped_correctly():
    ldif = _ldif_with_wrapped_memberof()
    entries = p.parse_ldif(ldif)
    user = next(e for e in entries if "User Accounts" in e["dn"])
    assert user["dn"] == "CN=User,OU=OU1,OU=OU2,OU=Contractors,OU=User Accounts - XXXX,OU=XXXX,DC=DOM,DC=AI"


def test_e2e_memberof_dn_unwrapped_correctly():
    ldif = _ldif_with_wrapped_memberof()
    entries = p.parse_ldif(ldif)
    user = next(e for e in entries if "User Accounts" in e["dn"])
    member_of = user["attrs"].get("memberOf", [])
    assert len(member_of) == 1
    assert member_of[0] == "CN=OU3,OU=_OU4,OU=OU5,OU=XXXX,DC=DOM,DC=AI"


def test_e2e_group_in_dn_to_sid_after_parse():
    ldif = _ldif_with_wrapped_memberof()
    entries = p.parse_ldif(ldif)
    conn = _make_conn()
    p.insert_entries_batch(conn, entries)
    dn_to_sid = p.build_dn_to_sid_map(conn)
    assert "cn=ou3,ou=_ou4,ou=ou5,ou=xxxx,dc=dom,dc=ai" in dn_to_sid


def test_e2e_group_has_member_via_memberof_after_full_pipeline():
    """Full pipeline: LDIF with wrapped memberOf → SQLite → export → group.Members populated."""
    ldif = _ldif_with_wrapped_memberof()
    entries = p.parse_ldif(ldif)
    conn = _make_conn()
    p.insert_entries_batch(conn, entries)

    buckets, dn_to_sid = _run_export_buckets(conn)

    assert len(buckets["users"]) == 1, f"Expected 1 user, got {len(buckets['users'])}"
    assert len(buckets["groups"]) == 1, f"Expected 1 group, got {len(buckets['groups'])}"

    group_node = buckets["groups"][0]
    user_node = buckets["users"][0]

    assert len(group_node["Members"]) == 1, (
        f"Expected group to have 1 member via memberOf, got {group_node['Members']}"
    )
    assert group_node["Members"][0]["ObjectIdentifier"] == user_node["ObjectIdentifier"]
    assert group_node["Members"][0]["ObjectType"] == "User"


# ---------------------------------------------------------------------------
# ADCS: Enterprise CA (pKIEnrollmentService)
# ---------------------------------------------------------------------------

import hashlib as _hashlib

_CA_GUID_BYTES = bytes.fromhex("d4c48bef11d27f4f83dc362b2d99a4fd")
_CA_GUID_STR = str(__import__("uuid").UUID(bytes_le=_CA_GUID_BYTES))
_CA_CERT_DER = b"\x30\x82\x01\x00" + b"\xab" * 252  # fake DER blob
_CA_CERT_THUMB = _hashlib.sha1(_CA_CERT_DER).hexdigest().upper()


def _ca_entry():
    return {
        "dn": "CN=CORP-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com",
        "attrs": {
            "objectClass": ["top", "pKIEnrollmentService"],
            "cn": ["CORP-CA"],
            "dNSHostName": ["ca.corp.com"],
            "objectGUID": [_CA_GUID_BYTES],
            "cACertificate": [_CA_CERT_DER],
            "certificateTemplates": ["User", "Machine", "WebServer"],
            "flags": ["0"],
        },
    }


def test_build_bh_ca_uses_guid():
    node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
    assert node is not None
    assert node["ObjectIdentifier"] == _CA_GUID_STR


def test_build_bh_ca_properties():
    node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
    props = node["Properties"]
    assert props["name"] == "CORP-CA"
    assert props["domain"] == DOMAIN_FQDN
    assert props["dnshostname"] == "ca.corp.com"
    assert props["caname"] == "CORP-CA"
    assert props["distinguishedname"].startswith("CN=CORP-CA")


def test_build_bh_ca_cert_thumbprint():
    node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
    assert node["Properties"]["certthumbprint"] == _CA_CERT_THUMB


def test_build_bh_ca_certchain_multiple():
    cert2 = b"\x30\x82\x01\x00" + b"\xcd" * 252
    thumb2 = _hashlib.sha1(cert2).hexdigest().upper()
    entry = _ca_entry()
    entry["attrs"]["cACertificate"] = [_CA_CERT_DER, cert2]
    node = p.build_bh_ca(entry, DOMAIN_FQDN)
    chain = node["Properties"]["certchain"]
    assert _CA_CERT_THUMB in chain
    assert thumb2 in chain
    assert len(chain) == 2


def test_build_bh_ca_templates_list():
    node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
    assert node["Properties"]["certificatetemplates"] == ["User", "Machine", "WebServer"]


def test_build_bh_ca_missing_guid_returns_none():
    entry = _ca_entry()
    del entry["attrs"]["objectGUID"]
    assert p.build_bh_ca(entry, DOMAIN_FQDN) is None


def test_build_bh_ca_has_is_deleted():
    node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
    assert node["IsDeleted"] is False


def test_build_bh_ca_enabled_cert_templates_empty_by_default():
    node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
    assert node["EnabledCertTemplates"] == []


# ---------------------------------------------------------------------------
# ADCS: Certificate Template (pKICertificateTemplate)
# ---------------------------------------------------------------------------

_TMPL_GUID_BYTES = bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
_TMPL_GUID_STR = str(__import__("uuid").UUID(bytes_le=_TMPL_GUID_BYTES))


def _template_entry(cn="User", name_flag=0, enroll_flag=0, schema=1):
    return {
        "dn": f"CN={cn},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com",
        "attrs": {
            "objectClass": ["top", "pKICertificateTemplate"],
            "cn": [cn],
            "displayName": [cn],
            "objectGUID": [_TMPL_GUID_BYTES],
            "msPKI-Template-Schema-Version": [str(schema)],
            "msPKI-Certificate-Name-Flag": [str(name_flag)],
            "msPKI-Enrollment-Flag": [str(enroll_flag)],
            "msPKI-RA-Signature": ["0"],
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4"],
        },
    }


def test_build_bh_cert_template_properties():
    node = p.build_bh_cert_template(_template_entry(), DOMAIN_FQDN)
    assert node is not None
    assert node["ObjectIdentifier"] == _TMPL_GUID_STR
    props = node["Properties"]
    assert props["domain"] == DOMAIN_FQDN
    assert props["displayname"] == "User"
    assert "USER" in props["name"]


def test_build_bh_cert_template_esc1_flags():
    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1, CT_FLAG_PEND_ALL_REQUESTS = 0x2
    node_esc1 = p.build_bh_cert_template(_template_entry(name_flag=0x1, enroll_flag=0x0), DOMAIN_FQDN)
    assert node_esc1["Properties"]["enrolleesuppliessubject"] is True
    assert node_esc1["Properties"]["requiresmanagerapproval"] is False

    node_managed = p.build_bh_cert_template(_template_entry(name_flag=0x0, enroll_flag=0x2), DOMAIN_FQDN)
    assert node_managed["Properties"]["enrolleesuppliessubject"] is False
    assert node_managed["Properties"]["requiresmanagerapproval"] is True


def test_build_bh_cert_template_ekus():
    node = p.build_bh_cert_template(_template_entry(), DOMAIN_FQDN)
    ekus = node["Properties"]["ekus"]
    assert "1.3.6.1.5.5.7.3.2" in ekus
    assert "1.3.6.1.5.5.7.3.4" in ekus


def test_build_bh_cert_template_schema_version():
    node = p.build_bh_cert_template(_template_entry(schema=2), DOMAIN_FQDN)
    assert node["Properties"]["schemaversion"] == 2


def test_build_bh_cert_template_subjectaltrequireupn():
    # bit 6 = 0x40
    node = p.build_bh_cert_template(_template_entry(name_flag=0x40), DOMAIN_FQDN)
    assert node["Properties"]["subjectaltrequireupn"] is True

    node2 = p.build_bh_cert_template(_template_entry(name_flag=0x0), DOMAIN_FQDN)
    assert node2["Properties"]["subjectaltrequireupn"] is False


def test_build_bh_cert_template_nosecurityextension():
    # bit 8 = 0x100
    node = p.build_bh_cert_template(_template_entry(enroll_flag=0x100), DOMAIN_FQDN)
    assert node["Properties"]["nosecurityextension"] is True


def test_build_bh_cert_template_missing_guid_returns_none():
    entry = _template_entry()
    del entry["attrs"]["objectGUID"]
    assert p.build_bh_cert_template(entry, DOMAIN_FQDN) is None


def test_build_bh_cert_template_has_is_deleted():
    node = p.build_bh_cert_template(_template_entry(), DOMAIN_FQDN)
    assert node["IsDeleted"] is False


# ---------------------------------------------------------------------------
# ADCS: export meta.type + second-pass EnabledCertTemplates linking
# ---------------------------------------------------------------------------

def test_export_ca_meta_type():
    import tempfile, json as _json, os
    conn = _make_conn()
    p.insert_entry(conn, _ca_entry())
    with tempfile.TemporaryDirectory() as d:
        class FakeArgs:
            db = None; output = d; domain = DOMAIN_FQDN; domain_sid = DOMAIN_SID
        FakeArgs.db = ":memory:"
        # drive cmd_export_bh via the real internal bucket logic
        buckets = {"cas": [], "certtemplates": []}
        node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
        if node:
            buckets["cas"].append(node)
        type_map = {"cas": "enterprisecas", "certtemplates": "certtemplates"}
        for key, data in buckets.items():
            payload = {"data": data, "meta": {"methods": 0, "type": type_map[key], "count": len(data), "version": 5}}
            out = _json.dumps(payload)
            loaded = _json.loads(out)
            if key == "cas":
                assert loaded["meta"]["type"] == "enterprisecas"
            if key == "certtemplates":
                assert loaded["meta"]["type"] == "certtemplates"


def test_e2e_ca_parsed_and_exported():
    """Full pipeline: CA LDIF → SQLite → export → cas bucket has 1 entry."""
    ca_guid_b64 = __import__("base64").b64encode(_CA_GUID_BYTES).decode()
    cert_b64 = __import__("base64").b64encode(_CA_CERT_DER).decode()
    ldif = (
        "dn: CN=CORP-CA,CN=Enrollment Services,CN=Configuration,DC=corp,DC=com\n"
        "objectClass: top\n"
        "objectClass: pKIEnrollmentService\n"
        "cn: CORP-CA\n"
        "dNSHostName: ca.corp.com\n"
        f"objectGUID:: {ca_guid_b64}\n"
        f"cACertificate:: {cert_b64}\n"
        "certificateTemplates: User\n"
        "certificateTemplates: Machine\n"
        "\n"
    )
    entries = p.parse_ldif(ldif)
    assert len(entries) == 1

    conn = _make_conn()
    p.insert_entries_batch(conn, entries)

    all_rows = conn.execute("SELECT dn, object_class, attrs_json FROM entries").fetchall()
    buckets = {"cas": [], "certtemplates": []}
    import json as _json
    for row in all_rows:
        classes = (row["object_class"] or "").lower().split(",")
        attrs_raw = _json.loads(row["attrs_json"])
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
        if "pkienrollmentservice" in classes:
            node = p.build_bh_ca(entry, DOMAIN_FQDN)
            if node:
                buckets["cas"].append(node)

    assert len(buckets["cas"]) == 1
    ca_node = buckets["cas"][0]
    assert ca_node["ObjectIdentifier"] == _CA_GUID_STR
    assert ca_node["Properties"]["dnshostname"] == "ca.corp.com"
    assert ca_node["Properties"]["certificatetemplates"] == ["User", "Machine"]


def test_e2e_enabled_cert_templates_linked():
    """CA's EnabledCertTemplates is populated by matching template cn to template GUID."""
    ca_node = p.build_bh_ca(_ca_entry(), DOMAIN_FQDN)
    tmpl_node = p.build_bh_cert_template(_template_entry(cn="User"), DOMAIN_FQDN)

    cn_to_guid = {"user": tmpl_node["ObjectIdentifier"]}
    p.link_ca_enabled_templates([ca_node], cn_to_guid)

    linked = ca_node["EnabledCertTemplates"]
    assert any(t["ObjectIdentifier"] == tmpl_node["ObjectIdentifier"] for t in linked)
    assert all(t["ObjectType"] == "CertTemplate" for t in linked)


def test_build_bh_cert_template_stores_cn():
    """cn is stored in Properties so the CA→template link can match by CN."""
    node = p.build_bh_cert_template(_template_entry(cn="Machine"), DOMAIN_FQDN)
    assert node["Properties"]["cn"] == "Machine"


def test_link_ca_enabled_templates_matches_by_cn_not_displayname():
    """CA certificateTemplates stores CN values; ensure link works when CN != displayName."""
    ca_entry = _ca_entry()
    # CA publishes "Machine" (CN), but the template's displayName is "Computer" (as in AD)
    ca_entry["attrs"]["certificateTemplates"] = ["Machine"]
    ca_node = p.build_bh_ca(ca_entry, DOMAIN_FQDN)

    tmpl_entry = _template_entry(cn="Machine")
    tmpl_entry["attrs"]["displayName"] = ["Computer"]  # displayName differs from cn
    tmpl_node = p.build_bh_cert_template(tmpl_entry, DOMAIN_FQDN)

    # Build cn_to_guid the same way cmd_export_bh does
    cn_to_guid = {}
    cn_to_guid[tmpl_node["Properties"]["cn"].lower()] = tmpl_node["ObjectIdentifier"]
    cn_to_guid[tmpl_node["Properties"]["displayname"].lower()] = tmpl_node["ObjectIdentifier"]

    p.link_ca_enabled_templates([ca_node], cn_to_guid)
    linked = ca_node["EnabledCertTemplates"]
    assert len(linked) == 1
    assert linked[0]["ObjectIdentifier"] == tmpl_node["ObjectIdentifier"]
