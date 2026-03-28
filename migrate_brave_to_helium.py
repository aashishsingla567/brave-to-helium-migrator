#!/usr/bin/env python3
import argparse
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


IV_HEX = (b" " * 16).hex()
SALT = b"saltysalt"
PBKDF2_ITERATIONS = 1003
KEY_LEN = 16

HOME = Path.home()
DEFAULT_BRAVE_ROOT = HOME / "Library/Application Support/BraveSoftware/Brave-Browser"
DEFAULT_HELIUM_ROOT = HOME / "Library/Application Support/net.imput.helium"
DEFAULT_HELIUM_BINARY = Path("/Applications/Helium.app/Contents/MacOS/Helium")
DEFAULT_KEYCHAIN = HOME / "Library/Keychains/login.keychain-db"

BRAVE_SAFE_STORAGE_SERVICE = "Brave Safe Storage"
BRAVE_SAFE_STORAGE_ACCOUNT = "Brave"
HELIUM_SAFE_STORAGE_SERVICE = "Helium Storage Key"
HELIUM_SAFE_STORAGE_ACCOUNT = "Helium"

ROOT_TEMPLATE_FILES = [
    "First Run",
    "Last Browser",
    "Last Version",
]

PROFILE_COPY_FILES = [
    "Bookmarks",
    "Bookmarks.bak",
    "Preferences",
    "Secure Preferences",
    "TransportSecurity",
    "Network Persistent State",
]

PROFILE_COPY_DIRS = [
    "Extensions",
    "Extension Rules",
    "Extension Scripts",
    "Extension State",
    "Local App Settings",
    "Local Extension Settings",
    "Platform Notifications",
    "Session Storage",
    "Shared Dictionary",
    "Sync Extension Settings",
]

OPTIONAL_SITE_STORAGE_DIRS = [
    "File System",
    "IndexedDB",
    "Local Storage",
    "Service Worker",
    "Storage",
    "WebStorage",
]


DB_PLANS = {
    "Login Data": {
        "skip_tables": {"meta"},
        "encrypted_cols": {"logins": {"password_value"}},
    },
    "Login Data For Account": {
        "skip_tables": {"meta"},
        "encrypted_cols": {"logins": {"password_value"}},
    },
    "Cookies": {
        "skip_tables": {"meta"},
        "encrypted_cols": {"cookies": {"encrypted_value"}},
    },
    "Web Data": {
        "skip_tables": {"meta"},
        "encrypted_cols": {
            "credit_cards": {"card_number_encrypted"},
            "local_ibans": {"value_encrypted"},
            "local_stored_cvc": {"value_encrypted"},
            "server_stored_cvc": {"value_encrypted"},
            "generic_payment_instruments": {"serialized_value_encrypted"},
            "payment_instrument_creation_options": {"serialized_value_encrypted"},
            "autofill_ai_attributes": {"value_encrypted"},
            "token_service": {"encrypted_token"},
        },
    },
    "Account Web Data": {
        "skip_tables": {"meta"},
        "encrypted_cols": {
            "credit_cards": {"card_number_encrypted"},
            "local_ibans": {"value_encrypted"},
            "local_stored_cvc": {"value_encrypted"},
            "server_stored_cvc": {"value_encrypted"},
            "generic_payment_instruments": {"serialized_value_encrypted"},
            "payment_instrument_creation_options": {"serialized_value_encrypted"},
        },
    },
    "History": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
    "Favicons": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
    "Top Sites": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
    "Shortcuts": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
    "Trust Tokens": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
    "Reporting and NEL": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
    "ServerCertificate": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
    "MediaDeviceSalts": {
        "skip_tables": {"meta"},
        "encrypted_cols": {},
    },
}


VERIFY_TABLES = [
    ("Login Data", "logins"),
    ("Cookies", "cookies"),
    ("History", "urls"),
    ("Top Sites", "top_sites"),
    ("Shortcuts", "omni_box_shortcuts"),
]

VERIFY_WEB_DATA = ["autofill", "addresses", "credit_cards", "keywords"]


def run(cmd, check=True, input_text=None):
    return subprocess.run(
        cmd,
        check=check,
        capture_output=True,
        text=True,
        input=input_text,
    )


def info(msg):
    print(msg, flush=True)


def close_app(name: str):
    subprocess.run(
        ["osascript", "-e", f'tell application "{name}" to quit'],
        capture_output=True,
        text=True,
    )


def close_browsers():
    close_app("Brave Browser")
    close_app("Helium")
    time.sleep(2)


def unlock_keychain(keychain: Path, password: str | None):
    if not password:
        return
    run(["security", "unlock-keychain", "-p", password, str(keychain)])


def keychain_secret(keychain: Path, service: str, account: str) -> str:
    result = run(
        [
            "security",
            "find-generic-password",
            "-w",
            "-s",
            service,
            "-a",
            account,
            str(keychain),
        ]
    )
    return result.stdout.strip()


def derive_key(password: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha1", password.encode(), SALT, PBKDF2_ITERATIONS, dklen=KEY_LEN
    )


def openssl_cbc(data: bytes, key: bytes, decrypt: bool) -> bytes:
    cmd = ["openssl", "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", IV_HEX, "-nopad"]
    if decrypt:
        cmd.insert(2, "-d")
    return subprocess.run(cmd, input=data, capture_output=True, check=True).stdout


def transform_blob(blob, brave_key: bytes, helium_key: bytes):
    if blob is None or not isinstance(blob, (bytes, bytearray)):
        return blob
    raw = bytes(blob)
    if not raw.startswith(b"v10"):
        return raw

    try:
        decrypted = openssl_cbc(raw[3:], brave_key, True)
        pad = decrypted[-1]
        if pad < 1 or pad > 16 or decrypted[-pad:] != bytes([pad]) * pad:
            raise ValueError("invalid PKCS#7 padding")
        plaintext = decrypted[:-pad]
    except Exception:
        # Some Chromium stores use a different encoding path despite the v10 prefix.
        # Preserve the original bytes instead of failing the whole migration.
        return raw

    new_pad = 16 - (len(plaintext) % 16)
    repadded = plaintext + bytes([new_pad]) * new_pad
    return b"v10" + openssl_cbc(repadded, helium_key, False)


def backup_tree(target: Path, backup_root: Path, label: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_path = backup_root / f"{label}-{stamp}"
    shutil.copytree(target, backup_path)
    return backup_path


def replace_tree(src: Path, dst: Path):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def copy_path(src: Path, dst: Path):
    if not src.exists():
        return
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def ensure_destination_schema(src_con, dst_con, table_names: set[str], skip_tables: set[str]):
    managed_tables = table_names - skip_tables
    table_rows = src_con.execute(
        """
        select name, sql
        from sqlite_master
        where type='table' and name not like 'sqlite_%'
        """
    ).fetchall()
    dst_tables = {
        row[0]
        for row in dst_con.execute(
            "select name from sqlite_master where type='table' and name not like 'sqlite_%'"
        )
    }
    for name, sql in table_rows:
        if name in managed_tables and name not in dst_tables and sql:
            dst_con.execute(sql)

    extra_rows = src_con.execute(
        """
        select type, name, tbl_name, sql
        from sqlite_master
        where type in ('index', 'trigger', 'view')
          and name not like 'sqlite_%'
          and sql is not null
        """
    ).fetchall()
    existing = {
        (row[0], row[1])
        for row in dst_con.execute(
            "select type, name from sqlite_master where name not like 'sqlite_%'"
        )
    }
    for object_type, name, tbl_name, sql in extra_rows:
        if tbl_name in managed_tables and (object_type, name) not in existing and sql:
            dst_con.execute(sql)


def create_clean_helium_template(helium_binary: Path, keep: bool) -> Path:
    temp_root = Path(tempfile.mkdtemp(prefix="helium-template-"))
    proc = subprocess.Popen(
        [
            str(helium_binary),
            f"--user-data-dir={temp_root}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    local_state = temp_root / "Local State"
    profile_pref = temp_root / "Default" / "Preferences"
    deadline = time.time() + 20
    while time.time() < deadline:
        if local_state.exists() and profile_pref.exists():
            break
        time.sleep(0.5)
    else:
        proc.kill()
        raise RuntimeError("Helium did not initialize a clean template profile")

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)

    if not keep:
        info(f"Generated clean Helium template in {temp_root}")
    return temp_root


def sync_root_template(template_root: Path, helium_root: Path):
    helium_root.mkdir(parents=True, exist_ok=True)
    for name in ROOT_TEMPLATE_FILES:
        copy_path(template_root / name, helium_root / name)


def selected_profiles(brave_root: Path, brave_state: dict, requested: list[str] | None):
    order = brave_state.get("profile", {}).get("profiles_order", [])
    if not order:
        order = sorted(
            p.name for p in brave_root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))
        )
    if requested:
        order = [name for name in order if name in requested]
    return [name for name in order if (brave_root / name).is_dir()]


def delete_existing_helium_profiles(helium_root: Path):
    for child in helium_root.iterdir():
        if child.is_dir() and (child.name == "Default" or child.name.startswith("Profile ")):
            shutil.rmtree(child)


def import_database(
    db_name: str,
    src_root: Path,
    dst_root: Path,
    brave_key: bytes,
    helium_key: bytes,
):
    plan = DB_PLANS[db_name]
    src = src_root / db_name
    dst = dst_root / db_name
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)

    src_con = sqlite3.connect(src)
    dst_con = sqlite3.connect(dst)
    try:
        src_tables = {
            row[0]
            for row in src_con.execute(
                "select name from sqlite_master where type='table' and name not like 'sqlite_%'"
            )
        }
        dst_tables = {
            row[0]
            for row in dst_con.execute(
                "select name from sqlite_master where type='table' and name not like 'sqlite_%'"
            )
        }
        ensure_destination_schema(src_con, dst_con, src_tables, plan["skip_tables"])
        dst_tables = {
            row[0]
            for row in dst_con.execute(
                "select name from sqlite_master where type='table' and name not like 'sqlite_%'"
            )
        }
        tables = sorted((src_tables & dst_tables) - plan["skip_tables"])
        dst_con.execute("PRAGMA foreign_keys=OFF")
        dst_con.execute("BEGIN IMMEDIATE")
        for table in tables:
            src_cols = [r[1] for r in src_con.execute(f'pragma table_info("{table}")')]
            dst_cols = [r[1] for r in dst_con.execute(f'pragma table_info("{table}")')]
            common_cols = [col for col in dst_cols if col in src_cols]
            if not common_cols:
                continue

            quoted_cols = ", ".join(f'"{col}"' for col in common_cols)
            rows = src_con.execute(f'SELECT {quoted_cols} FROM "{table}"').fetchall()
            encrypted_cols = plan["encrypted_cols"].get(table, set())
            if encrypted_cols:
                index_by_col = {col: idx for idx, col in enumerate(common_cols)}
                rewritten = []
                for row in rows:
                    mutable = list(row)
                    for col in encrypted_cols:
                        if col in index_by_col:
                            mutable[index_by_col[col]] = transform_blob(
                                mutable[index_by_col[col]], brave_key, helium_key
                            )
                    rewritten.append(tuple(mutable))
                rows = rewritten

            dst_con.execute(f'DELETE FROM "{table}"')
            if rows:
                placeholders = ", ".join("?" for _ in common_cols)
                dst_con.executemany(
                    f'INSERT INTO "{table}" ({quoted_cols}) VALUES ({placeholders})',
                    rows,
                )
        dst_con.commit()
    except Exception:
        dst_con.rollback()
        raise
    finally:
        src_con.close()
        dst_con.close()

    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = dst.parent / f"{dst.name}{suffix}"
        if sidecar.exists():
            sidecar.unlink()


def copy_profile_overlay(src_root: Path, dst_root: Path, include_site_storage: bool):
    for name in PROFILE_COPY_FILES:
        copy_path(src_root / name, dst_root / name)
    for name in PROFILE_COPY_DIRS:
        copy_path(src_root / name, dst_root / name)
    if include_site_storage:
        for name in OPTIONAL_SITE_STORAGE_DIRS:
            copy_path(src_root / name, dst_root / name)


def count_bookmarks(bookmarks_path: Path):
    if not bookmarks_path.exists():
        return {"bookmark_bar": 0, "other": 0, "synced": 0}
    data = json.loads(bookmarks_path.read_text())
    roots = data["roots"]

    def count_urls(node):
        if isinstance(node, dict):
            total = 1 if node.get("type") == "url" else 0
            for child in node.get("children", []):
                total += count_urls(child)
            return total
        return 0

    return {
        "bookmark_bar": count_urls(roots.get("bookmark_bar", {})),
        "other": count_urls(roots.get("other", {})),
        "synced": count_urls(roots.get("synced", {})),
    }


def verify_profile(profile_root: Path):
    summary = {"Bookmarks": count_bookmarks(profile_root / "Bookmarks")}
    for db_name, table in VERIFY_TABLES:
        db_path = profile_root / db_name
        if not db_path.exists():
            summary[db_name] = None
            continue
        con = sqlite3.connect(db_path)
        try:
            row = con.execute(
                "select name from sqlite_master where type='table' and name=?",
                (table,),
            ).fetchone()
            summary[db_name] = (
                con.execute(f"select count(*) from {table}").fetchone()[0] if row else None
            )
        finally:
            con.close()

    web_data_path = profile_root / "Web Data"
    if not web_data_path.exists():
        for table in VERIFY_WEB_DATA:
            summary[f"Web Data {table}"] = None
        return summary

    con = sqlite3.connect(web_data_path)
    try:
        for table in VERIFY_WEB_DATA:
            row = con.execute(
                "select name from sqlite_master where type='table' and name=?",
                (table,),
            ).fetchone()
            summary[f"Web Data {table}"] = (
                con.execute(f"select count(*) from {table}").fetchone()[0] if row else None
            )
    finally:
        con.close()
    return summary


def migrate_profile(
    brave_profile: Path,
    template_profile: Path,
    helium_target: Path,
    brave_key: bytes,
    helium_key: bytes,
    include_site_storage: bool,
):
    replace_tree(template_profile, helium_target)
    copy_profile_overlay(brave_profile, helium_target, include_site_storage)
    for db_name in DB_PLANS:
        import_database(db_name, brave_profile, helium_target, brave_key, helium_key)
    return verify_profile(helium_target)


def rebuild_helium_local_state(template_state: dict, brave_state: dict, profile_names: list[str]):
    result = json.loads(json.dumps(template_state))
    brave_profile = brave_state.get("profile", {})
    result_profile = result.setdefault("profile", {})
    template_entry = (result_profile.get("info_cache", {}) or {}).get("Default", {})
    new_info = {}
    for internal_name in profile_names:
        brave_entry = (brave_profile.get("info_cache", {}) or {}).get(internal_name, {})
        entry = dict(template_entry)
        entry.update(brave_entry)
        entry["name"] = brave_entry.get("name", internal_name)
        new_info[internal_name] = entry

    result_profile["info_cache"] = new_info
    result_profile["profiles_order"] = profile_names
    result_profile["profiles_created"] = len(profile_names)
    brave_last_active = brave_profile.get("last_active_profiles", [])
    result_profile["last_active_profiles"] = [p for p in brave_last_active if p in profile_names]
    result_profile["last_used"] = brave_profile.get("last_used", profile_names[0])
    if result_profile["last_used"] not in profile_names:
        result_profile["last_used"] = profile_names[0]
    result_profile["picker_shown"] = True
    result_profile["show_picker_on_startup"] = False
    metrics = result_profile.setdefault("metrics", {})
    metrics["next_bucket_index"] = (
        max((v.get("metrics_bucket_index", 0) for v in new_info.values()), default=0) + 1
    )

    var_groups = result.get("variations_google_groups", {})
    result["variations_google_groups"] = {name: var_groups.get(name, []) for name in profile_names}
    return result


def parse_args():
    parser = argparse.ArgumentParser(
        description="End-to-end Brave to Helium profile migrator for macOS."
    )
    parser.add_argument("--brave-root", type=Path, default=DEFAULT_BRAVE_ROOT)
    parser.add_argument("--helium-root", type=Path, default=DEFAULT_HELIUM_ROOT)
    parser.add_argument("--helium-binary", type=Path, default=DEFAULT_HELIUM_BINARY)
    parser.add_argument("--backup-root", type=Path, default=HOME / "BrowserMigrations")
    parser.add_argument("--profiles", help="Comma-separated Brave profile directories to migrate")
    parser.add_argument("--include-site-storage", action="store_true")
    parser.add_argument("--keychain-password")
    parser.add_argument("--keychain-path", type=Path, default=DEFAULT_KEYCHAIN)
    parser.add_argument("--brave-safe-storage")
    parser.add_argument("--helium-safe-storage")
    parser.add_argument("--no-backup", action="store_true")
    parser.add_argument("--keep-temp-template", action="store_true")
    parser.add_argument("--no-launch", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.brave_root.exists():
        raise SystemExit(f"Brave root not found: {args.brave_root}")
    if not args.helium_binary.exists():
        raise SystemExit(f"Helium binary not found: {args.helium_binary}")

    close_browsers()

    args.backup_root.mkdir(parents=True, exist_ok=True)
    if args.helium_root.exists() and not args.no_backup:
        backup = backup_tree(args.helium_root, args.backup_root, "helium-root-pre-migration")
        info(f"Backup {backup}")

    unlock_keychain(args.keychain_path, args.keychain_password)
    brave_secret = args.brave_safe_storage or keychain_secret(
        args.keychain_path, BRAVE_SAFE_STORAGE_SERVICE, BRAVE_SAFE_STORAGE_ACCOUNT
    )
    helium_secret = args.helium_safe_storage or keychain_secret(
        args.keychain_path, HELIUM_SAFE_STORAGE_SERVICE, HELIUM_SAFE_STORAGE_ACCOUNT
    )
    brave_key = derive_key(brave_secret)
    helium_key = derive_key(helium_secret)

    brave_state = json.loads((args.brave_root / "Local State").read_text())
    requested = [item.strip() for item in args.profiles.split(",")] if args.profiles else None
    profile_names = selected_profiles(args.brave_root, brave_state, requested)
    if not profile_names:
        raise SystemExit("No Brave profiles selected for migration")

    template_root = create_clean_helium_template(args.helium_binary, args.keep_temp_template)
    try:
        template_local_state = json.loads((template_root / "Local State").read_text())
        template_profile = template_root / "Default"

        sync_root_template(template_root, args.helium_root)
        delete_existing_helium_profiles(args.helium_root)

        rebuilt_local_state = rebuild_helium_local_state(
            template_local_state, brave_state, profile_names
        )
        (args.helium_root / "Local State").write_text(json.dumps(rebuilt_local_state, indent=2))

        summaries = {}
        for profile_name in profile_names:
            info(f"Migrating {profile_name}")
            summaries[profile_name] = migrate_profile(
                args.brave_root / profile_name,
                template_profile,
                args.helium_root / profile_name,
                brave_key,
                helium_key,
                args.include_site_storage,
            )

        info("Migration summary")
        for profile_name, summary in summaries.items():
            info(f"[{profile_name}]")
            for key, value in summary.items():
                info(f"  {key}: {value}")
    finally:
        if not args.keep_temp_template:
            shutil.rmtree(template_root, ignore_errors=True)

    if not args.no_launch:
        run(["open", "-a", "/Applications/Helium.app"])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
