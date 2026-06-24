export class ValidationError extends Error {}

// Matches register-oidc-client.sh's own client-id regex. Keep in sync.
const CONTAINER_NAME_RE = /^[a-z0-9][a-z0-9_-]*$/;

export function validateContainerName(name: string): void {
    if (!CONTAINER_NAME_RE.test(name)) {
        throw new ValidationError(
            `container name must match ^[a-z0-9][a-z0-9_-]*$ (got: ${JSON.stringify(name)})`,
        );
    }
    if (name.length > 64) {
        throw new ValidationError(`container name too long (got ${name.length} chars, max 64)`);
    }
}

/**
 * Recompute the exact set of public hostnames an app is reachable under:
 * `<client_id>-<suffix>` for each configured suffix. The `<app>-<suffix>` join
 * is the fixed mesh-router subdomain convention; the suffix list is pure config
 * (see Config.hostSuffixes) so the registrar knows nothing about specific
 * domains or DNS providers.
 *
 *   suffixes ["wisera.inojob.com", "80-241-218-30.nip.io", "80-241-218-30.sslip.io"]
 *   -> appshield-demo-wisera.inojob.com,
 *      appshield-demo-80-241-218-30.nip.io,
 *      appshield-demo-80-241-218-30.sslip.io
 *
 * `clientId` is the PTR-attested container name — NOT anything the caller sent —
 * so an app can only ever get redirect URIs under its own hostnames. Hosts are
 * lowercased for comparison. Keep this `<app>-<suffix>` join in sync with the
 * Caddy-label generator and the AppShield gate — see SSO/AppShield host doc.
 */
export function computeAppHosts(clientId: string, hostSuffixes: readonly string[]): string[] {
    return hostSuffixes.map((suffix) => `${clientId}-${suffix}`.toLowerCase());
}

export interface ValidateRedirectOptions {
    clientId: string;
    // Exact hostnames allowed for this app, precomputed via computeAppHosts().
    allowedHosts: ReadonlySet<string>;
}

export function validateRedirectUri(uri: string, opts: ValidateRedirectOptions): void {
    if (typeof uri !== "string" || uri.length === 0 || uri.length > 2048) {
        throw new ValidationError(`redirect URI must be a non-empty string under 2048 chars`);
    }

    let url: URL;
    try {
        url = new URL(uri);
    } catch {
        throw new ValidationError(`invalid redirect URI: ${uri}`);
    }

    // https only — the redirect carries the auth code; never hand it to a
    // downgraded http origin. (All real app hosts are https behind the gateway.)
    if (url.protocol !== "https:") {
        throw new ValidationError(`redirect URI must use https:// (got: ${url.protocol})`);
    }

    // The host is the security boundary: it's where the IdP delivers the code,
    // and mesh-router routes each host to exactly one container. Require an exact
    // match against the recomputed allowlist. Path/query/fragment are NOT
    // constrained — different apps use different callback paths.
    const host = url.hostname.toLowerCase();
    if (!opts.allowedHosts.has(host)) {
        throw new ValidationError(
            `redirect URI host ${JSON.stringify(host)} is not allowed for app ${JSON.stringify(opts.clientId)}; ` +
                `expected one of: ${[...opts.allowedHosts].join(", ") || "(none configured)"}`,
        );
    }
}
