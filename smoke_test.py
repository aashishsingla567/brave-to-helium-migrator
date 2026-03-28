#!/usr/bin/env python3
import argparse
import importlib.util
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
MIGRATOR_PATH = REPO_ROOT / "migrate_brave_to_helium.py"
SPEC = importlib.util.spec_from_file_location("migrate_brave_to_helium", MIGRATOR_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run a disposable Brave-to-Helium migration smoke test."
    )
    parser.add_argument(
        "--brave-root",
        type=Path,
        default=MODULE.DEFAULT_BRAVE_ROOT,
    )
    parser.add_argument(
        "--helium-binary",
        type=Path,
        default=MODULE.DEFAULT_HELIUM_BINARY,
    )
    parser.add_argument(
        "--keychain-password",
        required=True,
    )
    parser.add_argument(
        "--launch-seconds",
        type=int,
        default=8,
        help="Seconds Helium must stay alive after launch.",
    )
    parser.add_argument(
        "--keep-temp-dir",
        action="store_true",
    )
    return parser.parse_args()


def count_rows(profile_root: Path, db_name: str, table_name: str):
    db_path = profile_root / db_name
    if not db_path.exists():
        return None
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            "select name from sqlite_master where type='table' and name=?",
            (table_name,),
        ).fetchone()
        if not row:
            return None
        return con.execute(f"select count(*) from {table_name}").fetchone()[0]
    finally:
        con.close()


def main():
    args = parse_args()
    temp_root = Path(tempfile.mkdtemp(prefix="brave-to-helium-smoke-"))
    helium_root = temp_root / "helium-root"
    backup_root = temp_root / "backups"
    helium_root.mkdir()
    backup_root.mkdir()

    try:
        migrate_cmd = [
            sys.executable,
            str(MIGRATOR_PATH),
            "--brave-root",
            str(args.brave_root),
            "--helium-root",
            str(helium_root),
            "--backup-root",
            str(backup_root),
            "--helium-binary",
            str(args.helium_binary),
            "--keychain-password",
            args.keychain_password,
            "--no-launch",
        ]
        migrate = subprocess.run(
            migrate_cmd, capture_output=True, text=True, check=False
        )
        if migrate.returncode != 0:
            print(migrate.stdout, end="")
            print(migrate.stderr, end="", file=sys.stderr)
            raise SystemExit(migrate.returncode)

        state = json.loads((helium_root / "Local State").read_text())
        last_used = state["profile"]["last_used"]

        launch_cmd = [
            str(args.helium_binary),
            f"--user-data-dir={helium_root}",
            f"--profile-directory={last_used}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ]
        proc = subprocess.Popen(
            launch_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(args.launch_seconds)
        if proc.poll() is not None:
            raise RuntimeError("Helium exited during smoke-test launch window")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

        print("Smoke test passed")
        print(f"Temp root: {temp_root}")
        print(f"Profiles: {state['profile']['profiles_order']}")
        print(
            "Names:",
            {k: v.get("name") for k, v in state["profile"]["info_cache"].items()},
        )
        for profile_name in state["profile"]["profiles_order"]:
            profile_root = helium_root / profile_name
            print(f"[{profile_name}]")
            print("  Bookmarks:", MODULE.count_bookmarks(profile_root / "Bookmarks"))
            print("  Login Data:", count_rows(profile_root, "Login Data", "logins"))
            print("  Cookies:", count_rows(profile_root, "Cookies", "cookies"))
            print("  History:", count_rows(profile_root, "History", "urls"))
    finally:
        if not args.keep_temp_dir:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
