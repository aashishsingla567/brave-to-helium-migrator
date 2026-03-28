#!/usr/bin/env python3
import argparse
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


IV_HEX = (b" " * 16).hex()
SALT = b"saltysalt"
PBKDF2_ITERATIONS = 1003
KEY_LEN = 16


DIRECT_COPY_FILES = [
    "Bookmarks",
    "Bookmarks.bak",
    "TransportSecurity",
    "Network Persistent State",
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


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True)


def close_helium():
    subprocess.run(
        ["osascript", "-e", 'tell application "Helium" to quit'],
        capture_output=True,
        text=True,
    )
    time.sleep(2)


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
    if not bytes(blob).startswith(b"v10"):
        return bytes(blob)

    try:
        decrypted = openssl_cbc(bytes(blob)[3:], brave_key, True)
        pad = decrypted[-1]
        if pad < 1 or pad > 16 or decrypted[-pad:] != bytes([pad]) * pad:
            raise ValueError("invalid PKCS#7 padding")
        plaintext = decrypted[:-pad]
    except Exception:
        # Some stored values use a different encoding path despite the v10 prefix.
        # Preserve those bytes rather than aborting the whole migration.
        return bytes(blob)
    new_pad = 16 - (len(plaintext) % 16)
    repadded = plaintext + bytes([new_pad]) * new_pad
    return b"v10" + openssl_cbc(repadded, helium_key, False)


def replace_tree_from_snapshot(snapshot: Path, target: Path):
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(snapshot, target)


def backup_tree(target: Path, backup_root: Path, label: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_path = backup_root / f"{label}-{stamp}"
    shutil.copytree(target, backup_path)
    return backup_path


def copy_stable_files(src_root: Path, dst_root: Path):
    for name in DIRECT_COPY_FILES:
        src = src_root / name
        dst = dst_root / name
        if src.exists():
            shutil.copy2(src, dst)


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
    if not src.exists() or not dst.exists():
        return

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
                    f'INSERT INTO "{table}" ({quoted_cols}) VALUES ({placeholders})', rows
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


def count_bookmarks(bookmarks_path: Path):
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
    print("Bookmarks", count_bookmarks(profile_root / "Bookmarks"))
    for db_name, table in VERIFY_TABLES:
        con = sqlite3.connect(profile_root / db_name)
        try:
            count = con.execute(f"select count(*) from {table}").fetchone()[0]
        finally:
            con.close()
        print(db_name, count)

    con = sqlite3.connect(profile_root / "Web Data")
    try:
        for table in VERIFY_WEB_DATA:
            count = con.execute(f"select count(*) from {table}").fetchone()[0]
            print("Web Data", table, count)
    finally:
        con.close()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--brave-profile", required=True, type=Path)
    parser.add_argument("--helium-snapshot", required=True, type=Path)
    parser.add_argument("--helium-target", required=True, type=Path)
    parser.add_argument("--backup-root", required=True, type=Path)
    parser.add_argument("--backup-label", default="helium-profile-pre-migrate")
    parser.add_argument("--brave-safe-storage", required=True)
    parser.add_argument("--helium-safe-storage", required=True)
    parser.add_argument("--skip-close-helium", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.skip_close_helium:
        close_helium()

    if args.helium_target.exists():
        backup = backup_tree(args.helium_target, args.backup_root, args.backup_label)
        print("Backup", backup)

    replace_tree_from_snapshot(args.helium_snapshot, args.helium_target)
    brave_key = derive_key(args.brave_safe_storage)
    helium_key = derive_key(args.helium_safe_storage)

    copy_stable_files(args.brave_profile, args.helium_target)
    for db_name in DB_PLANS:
        import_database(db_name, args.brave_profile, args.helium_target, brave_key, helium_key)

    verify_profile(args.helium_target)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
