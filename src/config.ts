import { validateContainerName } from "./validation.js";

// Which OIDC provider backend client registration targets.
//   "authelia" (default) -> ShellRegistrar (register-oidc-client.sh) — current prod behavior.
//   "dex"                 -> DexGrpcRegistrar (Dex gRPC CreateClient).
export type RegistrarBackend = "authelia" | "dex";

export interface Config {
    port: number;
    issuerUrl: string;
    backend: RegistrarBackend;
    scriptPath: string;
    dexGrpcAddr: string;
    dexClientsDir: string;
    dnsResolver: string;
    maxRedirectUris: number;
    // Redirect-URI host allowlisting (exact recomputation). An app's allowed
    // hostnames are `<client_id>-<suffix>` for each configured suffix, and every
    // requested redirect URI's host must be an exact member. The code knows
    // NOTHING about domains or DNS providers — the suffix list is supplied
    // entirely by config (REDIRECT_HOST_SUFFIXES), so adding/removing a domain or
    // provider is a deployment change, never a code change. Example list:
    //   wisera.inojob.com, 80-241-218-30.nip.io, 80-241-218-30.sslip.io
    // -> appshield-demo-wisera.inojob.com,
    //    appshield-demo-80-241-218-30.nip.io,
    //    appshield-demo-80-241-218-30.sslip.io
    // The `<app>-<suffix>` join is the fixed mesh-router subdomain convention.
    hostSuffixes: string[];
    // The one app allowed to register callbacks on the BARE suffixes as well as
    // its own `<app>-<suffix>` hosts — i.e. whoever the PCS root domain proxies
    // to. Empty string = nobody, and the bare hostnames have no OIDC owner.
    // Sourced from ROOT_CLIENT_ID; see parseRootClientId.
    rootClientId: string;
}

// REDIRECT_HOST_SUFFIXES is a comma-separated list of host suffixes (the part
// after "<app>-"). Whitespace-trimmed, lowercased, de-duplicated, empties
// dropped. Unset/empty => no allowed hosts (the registrar then fails closed and
// rejects every redirect URI — see server.ts).
function parseHostSuffixes(raw: string | undefined): string[] {
    if (!raw) return [];
    const seen = new Set<string>();
    for (const part of raw.split(",")) {
        const s = part.trim().toLowerCase();
        if (s) seen.add(s);
    }
    return [...seen];
}

/**
 * ROOT_CLIENT_ID names the container the PCS root domain reverse-proxies to —
 * in practice the deployment feeds it Caddy's own DEFAULT_SERVICE_HOST, so the
 * app that OWNS the bare hostname and the app the bare hostname ROUTES to are
 * the same fact rather than two settings that can drift apart.
 *
 * That value is a proxy upstream target, not an identity: the Caddyfile
 * documents `host.docker.internal` as legal, the settings-center Domain panel
 * accepts dots and uppercase, and neither is a container name. So normalise and
 * run it through the same check as an attested name — anything that fails means
 * the root domain does not point at a container we can attest, and nobody gets
 * the bare hostnames. Fail closed and say so at boot; a silent "off" here looks
 * exactly like the bug this feature fixes.
 */
function parseRootClientId(raw: string | undefined): string {
    const value = (raw ?? "").trim().toLowerCase();
    if (!value) return "";
    try {
        validateContainerName(value);
        return value;
    } catch {
        console.warn(
            `[registrar] ROOT_CLIENT_ID ${JSON.stringify(raw)} is not a container name; ` +
                `no app may claim the bare redirect hosts`,
        );
        return "";
    }
}

export function loadConfig(): Config {
    const issuerUrl = process.env.ISSUER_URL;
    if (!issuerUrl || !/^https?:\/\//.test(issuerUrl)) {
        throw new Error("ISSUER_URL must be set to the OIDC issuer (e.g. https://auth-${DOMAIN})");
    }

    const port = parseInt(process.env.PORT ?? "9092", 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`PORT must be 1-65535 (got: ${process.env.PORT})`);
    }

    // Defaults to "authelia" so the Dex backend ships dormant — no behavior
    // change until REGISTRAR_BACKEND=dex is set at cutover.
    const backend = (process.env.REGISTRAR_BACKEND ?? "authelia") as RegistrarBackend;
    if (backend !== "authelia" && backend !== "dex") {
        throw new Error(`REGISTRAR_BACKEND must be 'authelia' or 'dex' (got: ${process.env.REGISTRAR_BACKEND})`);
    }

    return {
        port,
        issuerUrl: issuerUrl.replace(/\/+$/, ""),
        backend,
        scriptPath: process.env.REGISTER_SCRIPT_PATH ?? "/yundera/scripts/tools/register-oidc-client.sh",
        dexGrpcAddr: process.env.DEX_GRPC_ADDR ?? "dex:5557",
        dexClientsDir: process.env.DEX_CLIENTS_DIR ?? "/DATA/AppData/yundera/dex/clients",
        dnsResolver: process.env.DNS_RESOLVER ?? "127.0.0.11",
        // The root app registers 2x suffixes (its own `<app>-<suffix>` hosts plus
        // the bare ones), so this has to clear 2x the largest realistic suffix
        // list — today 3 (domain + nip.io + sslip.io), with IPv6 variants already
        // stubbed out in .pcs.env.
        maxRedirectUris: 20,
        hostSuffixes: parseHostSuffixes(process.env.REDIRECT_HOST_SUFFIXES),
        rootClientId: parseRootClientId(process.env.ROOT_CLIENT_ID),
    };
}
