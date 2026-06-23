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
    redirectUriHostnameSuffix: string | undefined;
    dnsResolver: string;
    maxRedirectUris: number;
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
        redirectUriHostnameSuffix: process.env.REDIRECT_URI_HOSTNAME_SUFFIX,
        dnsResolver: process.env.DNS_RESOLVER ?? "127.0.0.11",
        maxRedirectUris: 10,
    };
}
