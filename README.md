# mesh-router-auth

Internal-only HTTP service that auto-registers OIDC clients with the co-located Authelia instance. Lets hash-lock (and any other) sidecars bootstrap OIDC credentials from a drop-in compose file — no pre-provisioning, no shared secret to inject.

## What it does

A sidecar POSTs its redirect URIs to `http://auth-registrar:9092/register`. The registrar:

1. Identifies the caller via **PTR lookup of the source IP on the pcs network's embedded DNS** (`127.0.0.11`). The result is the caller's Docker `container_name`, which the app store already constrains to equal the store ID. `client_id` is derived, not accepted.
2. Validates each redirect URI's hostname: the first DNS label must equal `<client_id>` or start with `<client_id>-` (mesh-router routes `<app>-<user>.<domain>` to the container named `<app>`). Prevents app A from claiming app B's callback URL.
3. Shells out to the authoritative `register-oidc-client.sh` in template-root, which is idempotent and handles argon2 hashing + HUPing Authelia.
4. Returns `{client_id, client_secret, issuer_url}`.

## API

```
POST /register
Content-Type: application/json

{ "redirect_uris": ["https://myapp-alice.nsl.sh/nhl-auth/oidc/callback"] }
```

```
200 OK
{
  "client_id": "myapp",
  "client_secret": "a1b2c3...",
  "issuer_url": "https://auth-alice.nsl.sh"
}
```

```
GET /health → 200 {"status":"ok"}
```

Error codes:
- `400` — malformed request, invalid redirect URI, invalid PTR result
- `403` — PTR lookup failed (caller not on the expected Docker network)
- `500` — `register-oidc-client.sh` failed

## Security model

- **Never expose this service publicly.** Internal pcs network only. Use `expose:` in compose, never `ports:`.
- IP spoofing on a Docker bridge can't complete a TCP three-way handshake, so source-IP-derived identity is safe for this HTTP API.
- `container_name` uniqueness is enforced by Docker — duplicates are rejected at container start.
- Redirect-URI validation is the second line of defense: even with attestation, a compromised app must not be able to register a callback outside its own subdomain. The `ValidationError` tests (`src/tests/validation.spec.ts`) cover the typosquat cases (`myapp2.*`, `myappX.*`).

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ISSUER_URL` | yes | — | Authelia issuer URL (e.g. `https://auth-${DOMAIN}`). Returned to clients so they don't need to configure it. |
| `PORT` | no | `9092` | Listen port (pcs-internal). |
| `REGISTER_SCRIPT_PATH` | no | `/yundera/scripts/tools/register-oidc-client.sh` | Path to the script inside the container. |
| `REDIRECT_URI_HOSTNAME_SUFFIX` | no | — | If set, redirect URIs must end with this (e.g. `.nsl.sh`). Optional defense-in-depth; subdomain validation above is the primary check. |
| `DNS_RESOLVER` | no | `127.0.0.11` | Docker embedded DNS. Override only for testing. |

## Deployment

This service runs alongside Authelia in the PCS stack. Required mounts:

```yaml
auth-registrar:
  image: rg.fr-par.scw.cloud/aptero/mesh-router-auth:latest
  container_name: auth-registrar
  environment:
    ISSUER_URL: https://auth-${DOMAIN}
  volumes:
    # register-oidc-client.sh + library/log.sh + ensure-auth-secrets.sh
    - /DATA/AppData/casaos/apps/yundera:/yundera:ro
    # where the script writes clients.d/, secrets, etc.
    - /DATA/AppData/yundera/auth:/DATA/AppData/yundera/auth
    # script runs `docker run authelia/authelia ...` for argon2 hashing
    - /var/run/docker.sock:/var/run/docker.sock
  expose:
    - "9092"
  networks:
    pcs: null
  depends_on:
    - authelia
```

## Caller contract (hash-lock sidecar, etc.)

```ts
const res = await fetch("http://auth-registrar:9092/register", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    redirect_uris: [`https://${publicHostname}/nhl-auth/oidc/callback`],
  }),
});
const { client_id, client_secret, issuer_url } = await res.json();
```

Idempotent — the underlying script reprints the stored secret on re-registration. Callers don't need to persist the secret; they can re-fetch on every boot.

## Limitations

- `register-oidc-client.sh` currently **does not update** redirect URIs on re-registration with different URIs. If an app's hostname changes (rename, domain move), the existing client entry must be deleted first. Tracked for a future `--force` / `update` path in template-root.
- This service has docker socket access (to invoke argon2 hashing inside the Authelia image). That's the concentration-of-risk point — keep the attack surface minimal (no extra endpoints, no public exposure).

## Development

```bash
pnpm install
pnpm test          # mocha unit tests for validation + server
pnpm start         # tsc-watch, reload on change
pnpm build         # tsc → dist/
```
