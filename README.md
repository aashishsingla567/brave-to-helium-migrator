# Brave to Helium Migrator

Schema-aware Brave-to-Helium profile migration for macOS.

Current scope in this first commit:
- imports a single Brave profile into a single Helium profile
- re-encrypts Chromium `v10` blobs from Brave's macOS safe-storage key to Helium's
- preserves Helium's destination DB schemas while replacing shared user-data rows

The next commit will remove the remaining manual setup so the script can rebuild Helium directly from Brave on its own.
