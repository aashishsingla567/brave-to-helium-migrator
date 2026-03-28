import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "migrate_brave_to_helium.py"
SPEC = importlib.util.spec_from_file_location("migrate_brave_to_helium", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def encrypt_v10(plaintext: bytes, secret: str) -> bytes:
    key = MODULE.derive_key(secret)
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    return b"v10" + MODULE.openssl_cbc(padded, key, False)


def decrypt_v10(blob: bytes, secret: str) -> bytes:
    key = MODULE.derive_key(secret)
    decrypted = MODULE.openssl_cbc(blob[3:], key, True)
    pad = decrypted[-1]
    return decrypted[:-pad]


class MigrateTests(unittest.TestCase):
    def test_selected_profiles_uses_order_and_filters_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            brave_root = Path(tmp)
            (brave_root / "Default").mkdir()
            (brave_root / "Profile 4").mkdir()
            brave_state = {
                "profile": {
                    "profiles_order": ["Default", "Profile 3", "Profile 4"],
                }
            }
            self.assertEqual(
                MODULE.selected_profiles(brave_root, brave_state, None),
                ["Default", "Profile 4"],
            )

    def test_rebuild_helium_local_state_uses_brave_names(self):
        template_state = {
            "profile": {
                "info_cache": {
                    "Default": {
                        "avatar_icon": "chrome://theme/IDR_PROFILE_AVATAR_26",
                        "metrics_bucket_index": 3,
                    }
                },
                "last_used": "Default",
            },
            "variations_google_groups": {"Default": ["x"]},
        }
        brave_state = {
            "profile": {
                "info_cache": {
                    "Default": {"name": "Work", "metrics_bucket_index": 1},
                    "Profile 4": {"name": "coc123", "metrics_bucket_index": 5},
                },
                "last_used": "Profile 4",
                "last_active_profiles": ["Profile 4"],
            }
        }
        result = MODULE.rebuild_helium_local_state(
            template_state, brave_state, ["Default", "Profile 4"]
        )
        self.assertEqual(result["profile"]["profiles_order"], ["Default", "Profile 4"])
        self.assertEqual(result["profile"]["info_cache"]["Default"]["name"], "Work")
        self.assertEqual(result["profile"]["info_cache"]["Profile 4"]["name"], "coc123")
        self.assertEqual(result["profile"]["last_used"], "Profile 4")
        self.assertEqual(result["profile"]["last_active_profiles"], ["Profile 4"])
        self.assertEqual(result["profile"]["metrics"]["next_bucket_index"], 6)

    def test_copy_profile_overlay_copies_files_dirs_and_optional_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            dst = root / "dst"
            (src / "Extensions").mkdir(parents=True)
            (src / "Extensions" / "manifest.json").write_text("{}")
            (src / "Bookmarks").write_text('{"roots": {"bookmark_bar": {}, "other": {}, "synced": {}}}')
            (src / "IndexedDB").mkdir()
            (src / "IndexedDB" / "data.txt").write_text("x")
            dst.mkdir()

            MODULE.copy_profile_overlay(src, dst, include_site_storage=False)
            self.assertTrue((dst / "Extensions" / "manifest.json").exists())
            self.assertTrue((dst / "Bookmarks").exists())
            self.assertFalse((dst / "IndexedDB").exists())

            MODULE.copy_profile_overlay(src, dst, include_site_storage=True)
            self.assertTrue((dst / "IndexedDB" / "data.txt").exists())

    def test_transform_blob_reencrypts_between_browser_keys(self):
        plaintext = b"secret-value"
        brave_secret = "brave-secret"
        helium_secret = "helium-secret"
        source_blob = encrypt_v10(plaintext, brave_secret)
        transformed = MODULE.transform_blob(
            source_blob,
            MODULE.derive_key(brave_secret),
            MODULE.derive_key(helium_secret),
        )
        self.assertEqual(decrypt_v10(transformed, helium_secret), plaintext)

    def test_transform_blob_preserves_undecodable_payload(self):
        blob = b"v10" + b"\x00" * 16
        with mock.patch.object(MODULE, "openssl_cbc", return_value=b"\x00" * 16):
            result = MODULE.transform_blob(blob, b"a" * 16, b"b" * 16)
        self.assertEqual(result, blob)

    def test_import_database_reencrypts_login_rows_and_skips_meta(self):
        brave_secret = "brave-secret"
        helium_secret = "helium-secret"
        brave_key = MODULE.derive_key(brave_secret)
        helium_key = MODULE.derive_key(helium_secret)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_root = root / "src"
            dst_root = root / "dst"
            src_root.mkdir()
            dst_root.mkdir()
            src_db = src_root / "Login Data"
            dst_db = dst_root / "Login Data"

            src_con = sqlite3.connect(src_db)
            src_con.execute("create table meta(key longvarchar not null unique primary key, value longvarchar)")
            src_con.execute(
                "create table logins(username_value text, password_value blob)"
            )
            src_con.execute("insert into meta values('version', '1')")
            src_con.execute(
                "insert into logins values(?, ?)",
                ("alice", encrypt_v10(b'super-secret', brave_secret)),
            )
            src_con.commit()
            src_con.close()

            dst_con = sqlite3.connect(dst_db)
            dst_con.execute("create table meta(key longvarchar not null unique primary key, value longvarchar)")
            dst_con.execute(
                "create table logins(username_value text, password_value blob)"
            )
            dst_con.execute("insert into meta values('version', 'helium')")
            dst_con.execute("insert into logins values('old', x'')")
            dst_con.commit()
            dst_con.close()

            MODULE.import_database("Login Data", src_root, dst_root, brave_key, helium_key)

            con = sqlite3.connect(dst_db)
            meta = con.execute("select value from meta where key='version'").fetchone()[0]
            row = con.execute(
                "select username_value, password_value from logins"
            ).fetchone()
            con.close()

            self.assertEqual(meta, "helium")
            self.assertEqual(row[0], "alice")
            self.assertEqual(decrypt_v10(row[1], helium_secret), b"super-secret")

    def test_import_database_creates_missing_destination_table(self):
        brave_secret = "brave-secret"
        helium_secret = "helium-secret"
        brave_key = MODULE.derive_key(brave_secret)
        helium_key = MODULE.derive_key(helium_secret)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_root = root / "src"
            dst_root = root / "dst"
            src_root.mkdir()
            dst_root.mkdir()
            src_db = src_root / "Cookies"
            dst_db = dst_root / "Cookies"

            src_con = sqlite3.connect(src_db)
            src_con.execute("create table meta(key text primary key, value text)")
            src_con.execute(
                "create table cookies(host_key text, encrypted_value blob)"
            )
            src_con.execute(
                "insert into cookies values(?, ?)",
                ("example.com", encrypt_v10(b'cookie-secret', brave_secret)),
            )
            src_con.commit()
            src_con.close()

            dst_con = sqlite3.connect(dst_db)
            dst_con.execute("create table meta(key text primary key, value text)")
            dst_con.commit()
            dst_con.close()

            MODULE.import_database("Cookies", src_root, dst_root, brave_key, helium_key)

            con = sqlite3.connect(dst_db)
            row = con.execute(
                "select host_key, encrypted_value from cookies"
            ).fetchone()
            con.close()

            self.assertEqual(row[0], "example.com")
            self.assertEqual(decrypt_v10(row[1], helium_secret), b"cookie-secret")

    def test_import_database_creates_missing_destination_db_file(self):
        brave_secret = "brave-secret"
        helium_secret = "helium-secret"
        brave_key = MODULE.derive_key(brave_secret)
        helium_key = MODULE.derive_key(helium_secret)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_root = root / "src"
            dst_root = root / "dst"
            src_root.mkdir()
            dst_root.mkdir()
            src_db = src_root / "Cookies"

            src_con = sqlite3.connect(src_db)
            src_con.execute("create table cookies(host_key text, encrypted_value blob)")
            src_con.execute(
                "create index cookies_host_key_idx on cookies(host_key)"
            )
            src_con.execute(
                "insert into cookies values(?, ?)",
                ("example.org", encrypt_v10(b'cookie-secret-2', brave_secret)),
            )
            src_con.commit()
            src_con.close()

            MODULE.import_database("Cookies", src_root, dst_root, brave_key, helium_key)

            dst_db = dst_root / "Cookies"
            self.assertTrue(dst_db.exists())
            con = sqlite3.connect(dst_db)
            row = con.execute(
                "select host_key, encrypted_value from cookies"
            ).fetchone()
            idx = con.execute(
                "select name from sqlite_master where type='index' and name='cookies_host_key_idx'"
            ).fetchone()
            con.close()

            self.assertEqual(row[0], "example.org")
            self.assertEqual(decrypt_v10(row[1], helium_secret), b"cookie-secret-2")
            self.assertIsNotNone(idx)

    def test_verify_profile_tolerates_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.mkdir(exist_ok=True)
            summary = MODULE.verify_profile(root)
            self.assertEqual(summary["Bookmarks"], {"bookmark_bar": 0, "other": 0, "synced": 0})
            self.assertIsNone(summary["Login Data"])
            self.assertIsNone(summary["Web Data autofill"])

    def test_resolve_safe_storage_secrets_uses_cache_without_keychain(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "secrets.json"
            MODULE.write_secret_cache(
                cache_path,
                {
                    "brave_safe_storage": "brave-cached",
                    "helium_safe_storage": "helium-cached",
                },
            )
            args = SimpleNamespace(
                brave_safe_storage=None,
                helium_safe_storage=None,
                keychain_password="ignored",
                keychain_path=Path("/tmp/login.keychain-db"),
                secret_cache_path=cache_path,
            )
            with mock.patch.object(MODULE, "unlock_keychain") as unlock_mock, mock.patch.object(
                MODULE, "keychain_secret"
            ) as secret_mock:
                brave_secret, helium_secret = MODULE.resolve_safe_storage_secrets(args)
            self.assertEqual((brave_secret, helium_secret), ("brave-cached", "helium-cached"))
            unlock_mock.assert_not_called()
            secret_mock.assert_not_called()

    def test_resolve_safe_storage_secrets_writes_cache_after_keychain_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "secrets.json"
            args = SimpleNamespace(
                brave_safe_storage=None,
                helium_safe_storage=None,
                keychain_password="pw",
                keychain_path=Path("/tmp/login.keychain-db"),
                secret_cache_path=cache_path,
            )
            with mock.patch.object(MODULE, "unlock_keychain") as unlock_mock, mock.patch.object(
                MODULE,
                "keychain_secret",
                side_effect=["brave-live", "helium-live"],
            ) as secret_mock:
                brave_secret, helium_secret = MODULE.resolve_safe_storage_secrets(args)
            self.assertEqual((brave_secret, helium_secret), ("brave-live", "helium-live"))
            unlock_mock.assert_called_once()
            self.assertEqual(secret_mock.call_count, 2)
            payload = MODULE.load_secret_cache(cache_path)
            self.assertEqual(payload["brave_safe_storage"], "brave-live")
            self.assertEqual(payload["helium_safe_storage"], "helium-live")

    def test_resolve_safe_storage_secrets_persists_explicit_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "secrets.json"
            args = SimpleNamespace(
                brave_safe_storage="brave-explicit",
                helium_safe_storage="helium-explicit",
                keychain_password=None,
                keychain_path=Path("/tmp/login.keychain-db"),
                secret_cache_path=cache_path,
            )
            with mock.patch.object(MODULE, "unlock_keychain") as unlock_mock, mock.patch.object(
                MODULE, "keychain_secret"
            ) as secret_mock:
                brave_secret, helium_secret = MODULE.resolve_safe_storage_secrets(args)
            self.assertEqual((brave_secret, helium_secret), ("brave-explicit", "helium-explicit"))
            unlock_mock.assert_not_called()
            secret_mock.assert_not_called()
            payload = MODULE.load_secret_cache(cache_path)
            self.assertEqual(payload["brave_safe_storage"], "brave-explicit")
            self.assertEqual(payload["helium_safe_storage"], "helium-explicit")


if __name__ == "__main__":
    unittest.main()
