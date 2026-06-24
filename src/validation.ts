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

export interface AppHostParams {
    domain: string;
    publicIpDash: string;
    appHostTemplates: string[];
}

/**
 * Recompute the exact set of public hostnames an app is reachable under, using
 * the SAME formula the Caddy labels are generated from (always
 * `<app>-<userdomain>`, plus the IP-based fallback providers):
 *
 *   {APP}-{DOMAIN}            -> appshield-demo-wisera.inojob.com
 *   {APP}-{IP_DASH}.nip.io    -> appshield-demo-80-241-218-30.nip.io
 *   {APP}-{IP_DASH}.sslip.io  -> appshield-demo-80-241-218-30.sslip.io
 *
 * `clientId` is the PTR-attested container name — NOT anything the caller sent —
 * so an app can only ever get redirect URIs under its own hostnames. A template
 * whose required substitution value is empty is skipped (e.g. no PUBLIC_IP_DASH
 * configured => no nip.io/sslip.io hosts). Hosts are lowercased for comparison.
 *
 * Keep this formula in sync with the Caddy-label generator and the AppShield
 * gate (auth-service) — see SSO/AppShield host-formula doc.
 */
export function computeAppHosts(clientId: string, params: AppHostParams): string[] {
    const hosts: string[] = [];
    for (const tpl of params.appHostTemplates) {
        if (tpl.includes("{DOMAIN}") && !params.domain) continue;
        if (tpl.includes("{IP_DASH}") && !params.publicIpDash) continue;
        const host = tpl
            .split("{APP}").join(clientId)
            .split("{DOMAIN}").join(params.domain)
            .split("{IP_DASH}").join(params.publicIpDash)
            .toLowerCase();
        hosts.push(host);
    }
    return hosts;
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
