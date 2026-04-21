import { spawn } from "node:child_process";

export class RegistrationError extends Error {
    constructor(message: string, public readonly stderr: string = "") {
        super(message);
    }
}

export interface RegistrationResult {
    clientSecret: string;
}

export interface Registrar {
    register(clientId: string, redirectUris: string[]): Promise<RegistrationResult>;
}

/**
 * Shells out to register-oidc-client.sh in template-root.
 *
 * The script's contract (see mesh-router-template-root/scripts/tools/register-oidc-client.sh):
 *   - argv: <client-id> <redirect-uri> [<redirect-uri>...]
 *   - stdout: the plaintext client secret (nothing else — logs go to stderr via fd swap)
 *   - idempotent: re-running with the same client-id reprints the stored secret
 *   - re-renders configuration.yml and HUPs Authelia on success
 */
export class ShellRegistrar implements Registrar {
    constructor(
        private readonly scriptPath: string,
        private readonly timeoutMs: number = 60_000,
    ) {}

    register(clientId: string, redirectUris: string[]): Promise<RegistrationResult> {
        if (redirectUris.length === 0) {
            return Promise.reject(new RegistrationError("at least one redirect URI is required"));
        }

        return new Promise((resolve, reject) => {
            const proc = spawn(this.scriptPath, [clientId, ...redirectUris], {
                stdio: ["ignore", "pipe", "pipe"],
                timeout: this.timeoutMs,
            });

            let stdout = "";
            let stderr = "";
            proc.stdout.on("data", (chunk: Buffer) => {
                stdout += chunk.toString("utf8");
            });
            proc.stderr.on("data", (chunk: Buffer) => {
                stderr += chunk.toString("utf8");
            });

            proc.on("error", (err) => {
                reject(new RegistrationError(`failed to spawn ${this.scriptPath}: ${err.message}`));
            });

            proc.on("close", (code, signal) => {
                if (signal) {
                    reject(new RegistrationError(`script killed by signal ${signal}`, stderr));
                    return;
                }
                if (code !== 0) {
                    reject(new RegistrationError(`script exited with code ${code}`, stderr));
                    return;
                }
                const secret = stdout.trim();
                if (secret.length === 0) {
                    reject(new RegistrationError("script returned empty secret", stderr));
                    return;
                }
                resolve({ clientSecret: secret });
            });
        });
    }
}
