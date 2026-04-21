export interface Config {
    port: number;
    issuerUrl: string;
    scriptPath: string;
    redirectUriHostnameSuffix: string | undefined;
    dnsResolver: string;
    maxRedirectUris: number;
}

export function loadConfig(): Config {
    const issuerUrl = process.env.ISSUER_URL;
    if (!issuerUrl || !/^https?:\/\//.test(issuerUrl)) {
        throw new Error("ISSUER_URL must be set to the Authelia issuer (e.g. https://auth-${DOMAIN})");
    }

    const port = parseInt(process.env.PORT ?? "9092", 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`PORT must be 1-65535 (got: ${process.env.PORT})`);
    }

    return {
        port,
        issuerUrl: issuerUrl.replace(/\/+$/, ""),
        scriptPath: process.env.REGISTER_SCRIPT_PATH ?? "/yundera/scripts/tools/register-oidc-client.sh",
        redirectUriHostnameSuffix: process.env.REDIRECT_URI_HOSTNAME_SUFFIX,
        dnsResolver: process.env.DNS_RESOLVER ?? "127.0.0.11",
        maxRedirectUris: 10,
    };
}
