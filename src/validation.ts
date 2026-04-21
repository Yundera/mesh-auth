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

export interface ValidateRedirectOptions {
    clientId: string;
    hostnameSuffix: string | undefined;
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

    if (url.protocol !== "https:" && url.protocol !== "http:") {
        throw new ValidationError(
            `redirect URI must use http:// or https:// (got: ${url.protocol})`,
        );
    }

    if (opts.hostnameSuffix && !url.hostname.endsWith(opts.hostnameSuffix)) {
        throw new ValidationError(
            `redirect URI hostname must end with ${opts.hostnameSuffix}: ${uri}`,
        );
    }

    // The caller is identified by container_name (e.g. "myapp"). Mesh-router routes
    // subdomain "myapp-<user>.<domain>" to that container, so we accept either
    // "myapp.<domain>" (exact first-label match) or "myapp-<anything>.<domain>".
    // A trailing dash is required in the second case — this blocks "myapp2.<domain>",
    // "myappX.<domain>", etc. which would otherwise slip past a naive startsWith().
    const firstLabel = url.hostname.split(".")[0] ?? "";
    const okExact = firstLabel === opts.clientId;
    const okDashed = firstLabel.startsWith(opts.clientId + "-") && firstLabel.length > opts.clientId.length + 1;
    if (!okExact && !okDashed) {
        throw new ValidationError(
            `redirect URI hostname's first label (${JSON.stringify(firstLabel)}) must equal ${JSON.stringify(opts.clientId)} or start with ${JSON.stringify(opts.clientId + "-")}`,
        );
    }
}
