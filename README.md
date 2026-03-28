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

Run the test suite:

```bash
python3 -m unittest discover -s tests
```

Useful flags:

```bash
python3 migrate_brave_to_helium.py --profiles Default,Profile\\ 4
python3 migrate_brave_to_helium.py --include-site-storage
python3 migrate_brave_to_helium.py --keychain-password 'your-password'
python3 migrate_brave_to_helium.py --no-launch
```

Notes:
- The script keeps Helium's destination schemas and imports shared tables instead of replacing the DB files wholesale.
- Some Chromium stores can carry `v10` blobs that are not standard AES-CBC payloads. Those bytes are preserved unchanged instead of aborting the migration.
- `--include-site-storage` copies heavier browser storage trees too. Leave it off unless you specifically want that extra state and accept the higher compatibility risk.
