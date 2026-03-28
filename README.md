# Brave to Helium Migrator

Schema-aware Brave-to-Helium profile migration for macOS.

This is a vibe coded but tested and actually being used script. USE AT YOUR OWN RISK.

What the script now does on its own:
- closes Brave and Helium
- fetches Brave and Helium macOS safe-storage secrets from Keychain
- creates a fresh temporary Helium profile template by launching Helium into a temp user-data dir
- rebuilds Helium's profile map from Brave's `Local State`
- migrates all Brave profiles, preserving the same internal profile dirs and visible names
- re-encrypts Chromium `v10` blobs from Brave's safe-storage key to Helium's
- launches Helium when the migration finishes

Default paths:
- Brave root: `~/Library/Application Support/BraveSoftware/Brave-Browser`
- Helium root: `~/Library/Application Support/net.imput.helium`
- Helium binary: `/Applications/Helium.app/Contents/MacOS/Helium`

Usage:

```bash
python3 migrate_brave_to_helium.py
```

Zero-prompt mode:

```bash
BRAVE_SAFE_STORAGE='your-brave-safe-storage' \
HELIUM_SAFE_STORAGE='your-helium-safe-storage' \
python3 migrate_brave_to_helium.py
```

Or with explicit flags:

```bash
python3 migrate_brave_to_helium.py \
  --brave-safe-storage 'your-brave-safe-storage' \
  --helium-safe-storage 'your-helium-safe-storage'
```

Run the test suite:

```bash
python3 -m unittest discover -s tests
```

Run the disposable end-to-end smoke test:

```bash
python3 smoke_test.py --keychain-password 'your-password'
```

Useful flags:

```bash
python3 migrate_brave_to_helium.py --profiles Default,Profile\\ 4
python3 migrate_brave_to_helium.py --include-site-storage
python3 migrate_brave_to_helium.py --keychain-password 'your-password'
python3 migrate_brave_to_helium.py --brave-safe-storage '...' --helium-safe-storage '...'
python3 migrate_brave_to_helium.py --no-launch
```

Notes:
- The script keeps Helium's destination schemas and imports shared tables instead of replacing the DB files wholesale.
- Some Chromium stores can carry `v10` blobs that are not standard AES-CBC payloads. Those bytes are preserved unchanged instead of aborting the migration.
- `--include-site-storage` copies heavier browser storage trees too. Leave it off unless you specifically want that extra state and accept the higher compatibility risk.
- `smoke_test.py` is intentionally separate from the default unit suite because it uses the real Keychain, the real Helium binary, and a real disposable migrated profile.
- `--keychain-password` only unlocks the login keychain. macOS may still show per-item Keychain prompts. If you need truly non-interactive runs, use `--brave-safe-storage` and `--helium-safe-storage` or the corresponding environment variables.
