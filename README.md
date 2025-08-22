# Berry Chat Server

## Owner password encryption

Room owner passwords are encrypted at rest using AES-256-GCM. The encryption
key is derived from the `OWNER_PASS_KEY` environment variable. Make sure this
value is kept secret and never checked into source control. It should be stored
in a secure secret manager or an environment variable on the host.

### Key rotation

To rotate the encryption key:

1. Set the new key in `OWNER_PASS_KEY` and keep the old value in
   `OLD_OWNER_PASS_KEY` while running the migration.
2. Execute `node scripts/init-db.js` to re-encrypt all stored passwords using
   the new key.
3. Remove `OLD_OWNER_PASS_KEY` once migration completes.

If the database contains legacy plaintext passwords, running the migration
script once with only `OWNER_PASS_KEY` set will encrypt them in place.

