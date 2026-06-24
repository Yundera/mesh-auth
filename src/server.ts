import express, { Express, NextFunction, Request, Response } from "express";
import { Attestor, AttestationError } from "./attestation.js";
import { Config } from "./config.js";
import { Registrar, RegistrationError } from "./registration.js";
import { ValidationError, computeAppHosts, validateContainerName, validateRedirectUri } from "./validation.js";

export interface ServerDeps {
    config: Config;
    attestor: Attestor;
    registrar: Registrar;
}

interface RegisterRequestBody {
    redirect_uris?: unknown;
}

export function buildServer(deps: ServerDeps): Express {
    const { config, attestor, registrar } = deps;

    const app = express();
    app.disable("x-powered-by");
    app.use(express.json({ limit: "8kb" }));

    app.get("/health", (_req, res) => {
        res.status(200).json({ status: "ok" });
    });

    app.post("/register", async (req: Request, res: Response, next: NextFunction) => {
        try {
            const sourceIp = req.socket.remoteAddress;
            if (!sourceIp) {
                throw new ValidationError("cannot determine caller's source IP");
            }

            const clientId = await attestor.resolveContainerName(sourceIp);
            validateContainerName(clientId);

            // Independently recompute the exact hostnames this app may use, from
            // its PTR-attested identity — never from anything the caller sent.
            // The submitted redirect_uris are then verified to be a subset.
            const allowedHosts = new Set(
                computeAppHosts(clientId, {
                    domain: config.domain,
                    publicIpDash: config.publicIpDash,
                    appHostTemplates: config.appHostTemplates,
                }),
            );
            if (allowedHosts.size === 0) {
                throw new ValidationError(
                    `no allowed redirect hosts could be computed for app ${JSON.stringify(clientId)} ` +
                        `(check DOMAIN / PUBLIC_IP_DASH / APP_HOST_TEMPLATES)`,
                );
            }

            const body = req.body as RegisterRequestBody;
            const rawRedirects = body?.redirect_uris;
            if (!Array.isArray(rawRedirects) || rawRedirects.length === 0) {
                throw new ValidationError("redirect_uris must be a non-empty array");
            }
            if (rawRedirects.length > config.maxRedirectUris) {
                throw new ValidationError(
                    `too many redirect URIs (max ${config.maxRedirectUris}, got ${rawRedirects.length})`,
                );
            }

            const redirectUris: string[] = [];
            for (const uri of rawRedirects) {
                if (typeof uri !== "string") {
                    throw new ValidationError("each redirect_uris entry must be a string");
                }
                validateRedirectUri(uri, { clientId, allowedHosts });
                redirectUris.push(uri);
            }

            const { clientSecret } = await registrar.register(clientId, redirectUris);

            console.log(
                `[registrar] registered client_id=${clientId} redirects=${redirectUris.length} source=${sourceIp}`,
            );
            res.status(200).json({
                client_id: clientId,
                client_secret: clientSecret,
                issuer_url: config.issuerUrl,
            });
        } catch (err) {
            next(err);
        }
    });

    app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
        const sourceIp = req.socket.remoteAddress ?? "?";
        if (err instanceof ValidationError) {
            console.warn(`[registrar] 400 from ${sourceIp}: ${err.message}`);
            res.status(400).json({ error: err.message });
            return;
        }
        if (err instanceof AttestationError) {
            console.warn(`[registrar] 403 from ${sourceIp}: ${err.message}`);
            res.status(403).json({ error: `attestation failed: ${err.message}` });
            return;
        }
        if (err instanceof RegistrationError) {
            console.error(`[registrar] 500 from ${sourceIp}: ${err.message}\nstderr: ${err.stderr}`);
            res.status(500).json({ error: `registration failed: ${err.message}` });
            return;
        }
        console.error(`[registrar] 500 from ${sourceIp}:`, err);
        res.status(500).json({ error: "internal error" });
    });

    return app;
}
