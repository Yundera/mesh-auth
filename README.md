# mesh-router-auth

Internal-only HTTP service that auto-registers OIDC clients with the co-located Authelia instance. Lets hash-lock (and any other) sidecars bootstrap OIDC credentials from a drop-in compose file — no pre-provisioning, no shared secret to inject.

## What it does

A sidecar POSTs to `http://auth-registrar:9092/register`. The registrar:

1. Identifies the caller via **PTR lookup of the source IP on the pcs network's embedded DNS** (`127.0.0.11`). The result is the caller's Docker `container_name`, which the app store already constrains to equal the store ID. `client_id` is derived, not accepted.
2. Recomputes the exact hostnames that app may use — `<client_id>-<suffix>` for each configured suffix, plus the **bare** suffixes if it is the root app (see below). Never from anything the caller sent.
3. Registers the client with the configured backend (Dex gRPC `CreateClient`, or the legacy `register-oidc-client.sh` shell-out for Authelia). Both are idempotent.
4. Returns `{client_id, client_secret, issuer_url, redirect_uris}`.

## API

Two ways to state the callbacks. **Prefer `callback_path`** — the registrar then owns the host set, which is the only way a caller can pick up hosts that are not a function of its own name (see [The root app](#the-root-app)).

```
POST /register
Content-Type: application/json

{ "callback_path": "/nhl-auth/oidc/callback" }
```

```
200 OK
{
  "client_id": "myapp",
  "client_secret": "a1b2c3...",
  "issuer_url": "https://auth-alice.nsl.sh",
  "redirect_uris": [
    "https://myapp-alice.nsl.sh/nhl-auth/oidc/callback",
    "https://myapp-203-0-113-10.nip.io/nhl-auth/oidc/callback",
    "https://myapp-203-0-113-10.sslip.io/nhl-auth/oidc/callback"
  ]
}
```

The legacy form still works unchanged — send `redirect_uris` and each is verified against the same recomputed allowlist:

```
{ "redirect_uris": ["https://myapp-alice.nsl.sh/nhl-auth/oidc/callback"] }
```

`redirect_uris` is echoed in the response either way, so a caller can always adopt the authoritative list rather than recomputing it.

**Sending both is legal, and `callback_path` wins.** A caller that doesn't know whether it's talking to a registrar old enough to ignore `callback_path` sends both: the path for us, its own best guess for an older registrar. That combination must not error, and the path has to be the one that counts — the guess is exactly what gets the bare root hostname wrong.

```
GET /health → 200 {"status":"ok"}
```

Error codes:
- `400` — malformed request, invalid redirect URI or `callback_path`, invalid PTR result
- `403` — PTR lookup failed (caller not on the expected Docker network)
- `500` — backend registration failed

## The root app

Every app is reachable at `<app>-<suffix>`. One app is *also* reachable at each suffix **bare** — `wisera.inojob.com` as well as `maison-wisera.inojob.com` — because Caddy's root-domain block reverse-proxies the bare hostname to it.

That host is not derivable from the app's own name, so an app computing its own callback list always misses it. The gate then has no registrable callback on the host the user actually arrived at, and has to bounce them to `<app>-<suffix>` mid-login — which users experience as "SSO moved me to a different URL".

`ROOT_CLIENT_ID` names the container that owns the bare hostnames. The deployment feeds it Caddy's own `DEFAULT_SERVICE_HOST`, so *the app that owns the bare hostname* and *the app the bare hostname routes to* are one fact, not two settings that can drift.

It is compared against the PTR-attested `client_id`, so an app still cannot claim the bare hostname by asking — it has to actually be the container the root domain points at. Bare hosts are appended to the list, never prepended: callers treat entry 0 as their canonical origin, and for an AppShield running as an OAuth AS that value is the issuer baked into already-issued tokens.

`DEFAULT_SERVICE_HOST` is a proxy upstream target, not an identity — the Caddyfile documents `host.docker.internal` as legal, and the settings-center Domain panel accepts dots and uppercase. Anything that isn't a valid container name is rejected at boot and **nobody** gets the bare hostnames. The resolution is logged on startup:

```
[registrar] root app (may claim the bare suffixes): maison
[registrar] root app (may claim the bare suffixes): none
```

## Security model

- **Never expose this service publicly.** Internal pcs network only. Use `expose:` in compose, never `ports:`.
- IP spoofing on a Docker bridge can't complete a TCP three-way handshake, so source-IP-derived identity is safe for this HTTP API.
- `container_name` uniqueness is enforced by Docker — duplicates are rejected at container start.
- Redirect-URI validation is the second line of defense: even with attestation, a compromised app must not be able to register a callback outside its own subdomain. The `ValidationError` tests (`src/tests/validation.spec.ts`) cover the typosquat cases (`myapp2.*`, `myappX.*`).

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ISSUER_URL` | yes | — | OIDC issuer URL (e.g. `https://auth-${DOMAIN}`). Returned to clients so they don't need to configure it. |
| `PORT` | no | `9092` | Listen port (pcs-internal). |
| `REGISTRAR_BACKEND` | no | `authelia` | `dex` → Dex gRPC `CreateClient`; `authelia` → `register-oidc-client.sh` shell-out. |
| `REDIRECT_HOST_SUFFIXES` | no | — | Comma-separated host suffixes (the part after `<app>-`), e.g. `${DOMAIN},${PUBLIC_IP_DASH}.nip.io,${PUBLIC_IP_DASH}.sslip.io`. **Unset ⇒ fail closed**: every registration is rejected. Must list the same suffixes the apps' `caddy_*` labels use. |
| `ROOT_CLIENT_ID` | no | — | Container the root domain proxies to; the one app that may also register callbacks on the **bare** suffixes. Fed from Caddy's `DEFAULT_SERVICE_HOST`. Non-container values are rejected at boot and nobody claims the bare hosts. See [The root app](#the-root-app). |
| `DEX_GRPC_ADDR` | no | `dex:5557` | Dex gRPC endpoint (`REGISTRAR_BACKEND=dex`). Must be reachable only on an internal network — the API is unauthenticated. |
| `DEX_CLIENTS_DIR` | no | `/DATA/AppData/yundera/dex/clients` | Where issued client secrets are persisted (Dex never echoes them back). |
| `REGISTER_SCRIPT_PATH` | no | `/yundera/scripts/tools/register-oidc-client.sh` | Path to the script inside the container (`REGISTRAR_BACKEND=authelia`). |
| `DNS_RESOLVER` | no | `127.0.0.11` | Docker embedded DNS. Override only for testing. |

## Deployment

Current PCS shape (Dex backend, from template-root's `root/docker-compose.yml`):

```yaml
auth-registrar:
  image: ghcr.io/yundera/mesh-auth:1.2.0
  container_name: auth-registrar          # PTR-attested; apps reach it by this name
  environment:
    ISSUER_URL: https://auth-${DOMAIN}
    REGISTRAR_BACKEND: dex
    DEX_GRPC_ADDR: 172.31.7.2:5557        # isolated dex-internal net
    DEX_CLIENTS_DIR: /tmp/dex-clients
    # Must list the SAME suffixes the apps' caddy_* labels use.
    REDIRECT_HOST_SUFFIXES: "${DOMAIN},${PUBLIC_IP_DASH}.nip.io,${PUBLIC_IP_DASH}.sslip.io"
    # Caddy's root-domain upstream — the app that also owns the BARE suffixes.
    # Same variable that drives the Caddyfile's root block, deliberately: one
    # fact, so ownership and routing cannot disagree.
    ROOT_CLIENT_ID: "${DEFAULT_SERVICE_HOST}"
  expose:
    - "9092"
  networks:
    pcs: null           # /register from app sidecars + PTR attestation
    dex-internal: null  # gRPC to Dex
  depends_on:
    - dex
```

The legacy Authelia backend (`REGISTRAR_BACKEND=authelia`) instead needs `/DATA/AppData/casaos/apps/yundera:/yundera:ro`, `/DATA/AppData/yundera/auth`, and the Docker socket (the script shells out to `authelia/authelia` for argon2 hashing).

## Caller contract (hash-lock sidecar, etc.)

```ts
const res = await fetch("http://auth-registrar:9092/register", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    callback_path: "/nhl-auth/oidc/callback",
    // Only needed while older registrars are still in the field; they ignore
    // callback_path and require this. Newer ones ignore THIS. Drop once every
    // PCS is on >= 0.3.0.
    redirect_uris: ownGuessAtHosts.map((h) => `https://${h}/nhl-auth/oidc/callback`),
  }),
});
const { client_id, client_secret, issuer_url, redirect_uris } = await res.json();

// Use what came back, not what you guessed: redirect_uris is the authoritative
// set, and it is the only way to learn about hosts that are not a function of
// your own container name (the bare root domain).
const origins = new Set((redirect_uris ?? ownGuess).map((u) => new URL(u).origin));
```

Idempotent — the underlying script reprints the stored secret on re-registration. Callers don't need to persist the secret; they can re-fetch on every boot.

## Limitations

- **Changing the root app leaves a stale bare-host callback on the old one.** Redirect URIs are only synced when an app re-registers, so after `DEFAULT_SERVICE_HOST` moves from A to B, A's client still lists `https://<bare-domain>/…`. It is inert — A no longer *requests* that host, and a code delivered there now reaches B, which cannot exchange it without A's secret — but it is untidy. Clean it by having A re-register (a restart is enough), or prune bare-suffix URIs on any register where `client_id != ROOT_CLIENT_ID`.
- `register-oidc-client.sh` currently **does not update** redirect URIs on re-registration with different URIs. If an app's hostname changes (rename, domain move), the existing client entry must be deleted first. Tracked for a future `--force` / `update` path in template-root.
- This service has docker socket access (to invoke argon2 hashing inside the Authelia image). That's the concentration-of-risk point — keep the attack surface minimal (no extra endpoints, no public exposure).

## Development

```bash
pnpm install
pnpm test          # mocha unit tests for validation + server
pnpm start         # tsc-watch, reload on change
pnpm build         # tsc → dist/
```
