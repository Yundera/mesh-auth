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

export interface AllowedHostOptions {
    clientId: string;
    hostSuffixes: readonly string[];
    // The container the PCS root domain proxies to, or "" when nobody owns it.
    // See Config.rootClientId.
    rootClientId?: string;
}

/**
 * The full ordered host set an app may register callbacks on.
 *
 * Every app gets `<app>-<suffix>` (computeAppHosts above). The ONE app the root
 * domain proxies to additionally gets each suffix **bare** — `wisera.inojob.com`
 * as well as `maison-wisera.inojob.com` — because Caddy's root-domain block
 * routes the bare hostname to it. Without this, a login that starts on the bare
 * domain has no registrable callback there and the gate has to bounce the user
 * to `<app>-<suffix>` mid-flow, which is what users see as "SSO moved me to a
 * different URL".
 *
 * Bare hosts are appended, NEVER prepended: callers treat the first entry as
 * their canonical origin, and for an AppShield running as an OAuth AS that value
 * is the issuer baked into already-issued tokens and cached discovery documents.
 * Reordering this list silently rotates that issuer.
 *
 * `rootClientId` comes from deployment config and is compared against the
 * PTR-attested `clientId`, so an app still cannot claim the bare hostname by
 * asking — it has to actually be the container the root domain points at.
 */
export function computeAllowedHosts(opts: AllowedHostOptions): string[] {
    const { clientId, hostSuffixes, rootClientId } = opts;
    const hosts = computeAppHosts(clientId, hostSuffixes);

    if (rootClientId && rootClientId === clientId) {
        hosts.push(...hostSuffixes.map((suffix) => suffix.toLowerCase()));
    }

    // Order-preserving dedup. A suffix list that already contains an app's own
    // `<app>-<suffix>` host would otherwise register the same URI twice.
    return [...new Set(hosts)];
}

export interface ValidateRedirectOptions {
    clientId: string;
    // Exact hostnames allowed for this app, precomputed via computeAllowedHosts().
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

// Whitespace + C0/C1 control characters. URL parsing would percent-encode or
// strip these; rejecting is better than silently rewriting the caller's path.
const CTRL_OR_SPACE_RE = /[\s\x00-\x1f\x7f-\x9f]/;

/**
 * Validate a caller-supplied callback PATH, which the registrar then joins onto
 * every host it has independently decided the caller may use.
 *
 * The path is not a security boundary — validateRedirectUri deliberately does
 * not constrain it, because mesh-router routes a whole host to one container, so
 * anything under that host already belongs to the caller. What the checks here
 * buy is unambiguous concatenation: `https://<host>` + path must parse back to
 * the same host, with no way to smuggle an authority, a second scheme, or a
 * fragment (which RFC 6749 §3.1.2 forbids in a redirect URI) past the join.
 * Callers that need something exotic can still send explicit `redirect_uris`.
 */
export function validateCallbackPath(value: unknown): string {
    if (typeof value !== "string" || value.length === 0 || value.length > 512) {
        throw new ValidationError(`callback_path must be a non-empty string under 512 chars`);
    }
    if (!value.startsWith("/")) {
        throw new ValidationError(`callback_path must start with "/" (got: ${JSON.stringify(value)})`);
    }
    // "//host/x" is a protocol-relative reference and "/\evil" is normalised to
    // a double slash by browsers. Neither escapes the host once concatenated,
    // but both make the resulting URI mean something other than it reads.
    if (value.startsWith("//") || value.includes("\\")) {
        throw new ValidationError(`callback_path must not begin with "//" or contain a backslash`);
    }
    if (value.includes("#")) {
        throw new ValidationError(`callback_path must not contain a fragment`);
    }
    if (CTRL_OR_SPACE_RE.test(value)) {
        throw new ValidationError(`callback_path must not contain whitespace or control characters`);
    }
    if (value.split(/[/?]/).includes("..")) {
        throw new ValidationError(`callback_path must not contain ".." segments`);
    }
    return value;
}
