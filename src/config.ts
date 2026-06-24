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
    // Redirect-URI host allowlisting (exact recomputation). The set of public
    // hostnames an app is reachable under is recomputed here from the attested
    // client_id + these values, and each requested redirect URI's host must be
    // an exact member. Same formula the Caddy labels are generated from:
    //   {APP}-{DOMAIN}            -> appshield-demo-wisera.inojob.com
    //   {APP}-{IP_DASH}.nip.io    -> appshield-demo-80-241-218-30.nip.io
    //   {APP}-{IP_DASH}.sslip.io  -> appshield-demo-80-241-218-30.sslip.io
    // appHostTemplates is a configurable array so new domains/providers can be
    // added without code changes. A template whose required value (domain / ip)
    // is empty is skipped at compute time.
    domain: string;
    publicIpDash: string;
    appHostTemplates: string[];
}

const DEFAULT_APP_HOST_TEMPLATES = [
    "{APP}-{DOMAIN}",
    "{APP}-{IP_DASH}.nip.io",
    "{APP}-{IP_DASH}.sslip.io",
];

// The user domain (e.g. "wisera.inojob.com"). Prefer an explicit DOMAIN env;
// otherwise derive it from ISSUER_URL ("https://auth-<domain>").
function deriveDomain(issuerUrl: string): string {
    if (process.env.DOMAIN) return process.env.DOMAIN.replace(/^\.+/, "").toLowerCase();
    const m = issuerUrl.match(/^https?:\/\/auth-(.+)$/i);
    return m ? m[1].replace(/\/+$/, "").toLowerCase() : "";
}

function parseAppHostTemplates(raw: string | undefined): string[] {
    if (!raw) return DEFAULT_APP_HOST_TEMPLATES;
    let arr: unknown;
    try {
        arr = JSON.parse(raw);
    } catch {
        throw new Error("APP_HOST_TEMPLATES must be a JSON array of strings");
    }
    if (!Array.isArray(arr) || arr.length === 0 || arr.some((x) => typeof x !== "string" || x.length === 0)) {
        throw new Error("APP_HOST_TEMPLATES must be a non-empty JSON array of non-empty strings");
    }
    return arr as string[];
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

    const normalizedIssuer = issuerUrl.replace(/\/+$/, "");

    return {
        port,
        issuerUrl: normalizedIssuer,
        backend,
        scriptPath: process.env.REGISTER_SCRIPT_PATH ?? "/yundera/scripts/tools/register-oidc-client.sh",
        dexGrpcAddr: process.env.DEX_GRPC_ADDR ?? "dex:5557",
        dexClientsDir: process.env.DEX_CLIENTS_DIR ?? "/DATA/AppData/yundera/dex/clients",
        dnsResolver: process.env.DNS_RESOLVER ?? "127.0.0.11",
        maxRedirectUris: 10,
        domain: deriveDomain(normalizedIssuer),
        publicIpDash: (process.env.PUBLIC_IP_DASH ?? "").toLowerCase(),
        appHostTemplates: parseAppHostTemplates(process.env.APP_HOST_TEMPLATES),
    };
}
