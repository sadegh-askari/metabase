# Keycloak sign-in for Metabase Open Source

This fork adds Keycloak as an extra OIDC sign-in method while leaving Metabase password login enabled. It only links an
existing Metabase user after Keycloak returns a verified email that matches the Metabase account. It does not create
Metabase accounts, import Keycloak users, change profile fields, or replace password credentials.

## Keycloak client

Create a confidential client in the Keycloak realm used by your employees:

- Client authentication: enabled
- Standard flow: enabled
- Valid redirect URI: `https://metabase.example.com/auth/sso/keycloak/callback`
- Client scopes: `openid`, `email`, and `profile`
- Ensure the ID token includes a verified email claim (`email_verified: true`)

Use the exact realm issuer URL shown by Keycloak's OpenID configuration document, for example
`https://keycloak.example.com/realms/employees`.

## Metabase environment

Set these variables on the Metabase container and restart it:

```yaml
MB_SITE_URL: https://metabase.example.com
MB_OIDC_STATE_SECRET_KEY: <a stable, securely stored secret of at least 16 characters>
MB_KEYCLOAK_OIDC_ISSUER_URI: https://keycloak.example.com/realms/employees
MB_KEYCLOAK_OIDC_CLIENT_ID: metabase
MB_KEYCLOAK_OIDC_CLIENT_SECRET: <Keycloak client secret>
```

The Keycloak button appears only when all three `MB_KEYCLOAK_OIDC_*` values and a state-encryption key are present. Use
`MB_OIDC_STATE_SECRET_KEY` to encrypt the short-lived OIDC state cookie without changing encryption for existing Metabase database
values. Alternatively, `MB_ENCRYPTION_SECRET_KEY` can provide the OIDC state key; adding it to an existing instance requires the
documented one-time `enable-encryption` procedure. Keep whichever key you use stable across restarts and replicas.

## Existing users and matching

On first Keycloak sign-in, Metabase matches the verified email case-insensitively to an existing Metabase account and
stores Keycloak's stable `sub` as that account's Keycloak identity. Password hashes are left unchanged, so local
password login remains available. Future Keycloak logins resolve by the stored subject. A Keycloak identity already
linked to a different Metabase user, or a Metabase account already linked to another Keycloak subject, is refused.

If there is no matching Metabase account, sign-in is denied and no account is created. Existing Metabase-only users
remain unchanged and continue using their current credentials.
