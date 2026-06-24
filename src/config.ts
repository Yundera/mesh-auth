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
        maxRedirectUris: 10,
        hostSuffixes: parseHostSuffixes(process.env.REDIRECT_HOST_SUFFIXES),
    };
}
