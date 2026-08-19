import express, { Express, NextFunction, Request, Response } from "express";
import { Attestor, AttestationError } from "./attestation.js";
import { Config } from "./config.js";
import { Registrar, RegistrationError } from "./registration.js";
import {
    ValidationError,
    computeAllowedHosts,
    validateCallbackPath,
    validateContainerName,
    validateRedirectUri,
} from "./validation.js";

export interface ServerDeps {
    config: Config;
    attestor: Attestor;
    registrar: Registrar;
}

interface RegisterRequestBody {
    redirect_uris?: unknown;
    callback_path?: unknown;
    // Logout paths, both optional. Same contract as callback_path: the caller
    // states only the PATH and the registrar supplies the hosts, because the
    // host set is a property of the deployment, not of the app.
    post_logout_path?: unknown;
    backchannel_logout_path?: unknown;
}

interface RedirectUriOptions {
    clientId: string;
    allowedHosts: ReadonlySet<string>;
    max: number;
}

// Legacy path: the caller states the full URIs and we verify they are a subset
// of what it may have. Unchanged behaviour — this is what every AppShield before
// the callback_path contract sends, and what any non-AppShield caller sends.
function validateSubmittedRedirectUris(raw: unknown, opts: RedirectUriOptions): string[] {
    if (!Array.isArray(raw) || raw.length === 0) {
        throw new ValidationError("redirect_uris must be a non-empty array (or send callback_path)");
    }
    if (raw.length > opts.max) {
        throw new ValidationError(`too many redirect URIs (max ${opts.max}, got ${raw.length})`);
    }

    const uris: string[] = [];
    for (const uri of raw) {
        if (typeof uri !== "string") {
            throw new ValidationError("each redirect_uris entry must be a string");
        }
        validateRedirectUri(uri, opts);
        uris.push(uri);
    }
    return uris;
}

// Authoritative path: the caller states only its callback PATH and the registrar
// supplies the hosts. This is the whole point of the contract — the set of hosts
// an app is reachable under is a property of the deployment (which suffixes
// exist, which app the root domain points at), not something the app can derive
// from its own name.
//
// The result still goes through validateRedirectUri, so caller-supplied and
// registrar-derived URIs are governed by exactly one invariant rather than two
// that could drift.
// Back-channel logout is the ONE URI here that is not a browser redirect: Dex
// POSTs to it server-to-server. It therefore uses the container name on the
// internal `pcs` network rather than a public https host.
//
// That is a deliberate choice, not a shortcut. A public URL would leave the box,
// hit the gateway/CDN and come back in — a hairpin that is unreliable on exactly
// the NAT'd hosts this platform targets, and it would make a core auth mechanism
// depend on external DNS and TLS being healthy. Internally, `<client-id>` is the
// gate's container name by construction (the registrar attests it by PTR lookup
// of the caller), and both Dex and every gate sit on `pcs`.
//
// Consequently it does NOT go through validateRedirectUri: that helper requires
// https and a host from the attested public set, and neither applies to an
// intra-network POST. The identity guarantee here comes from the same PTR
// attestation that produced clientId.
function deriveBackchannelUri(clientId: string, rawPath: unknown): string {
    const path = validateCallbackPath(rawPath);
    return `http://${clientId}${path}`;
}

function deriveRedirectUris(hosts: readonly string[], rawPath: unknown, opts: RedirectUriOptions): string[] {
    const callbackPath = validateCallbackPath(rawPath);

    if (hosts.length > opts.max) {
        throw new ValidationError(
            `too many redirect URIs (max ${opts.max}, ${hosts.length} hosts configured)`,
        );
    }

    return hosts.map((host) => {
        const uri = `https://${host}${callbackPath}`;
        validateRedirectUri(uri, opts);
        return uri;
    });
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
            // its PTR-attested identity + the configured suffix list (+ the bare
            // suffixes if it is the root app) — never from anything the caller
            // sent. Empty list => fail closed (reject all).
            const allowedHostList = computeAllowedHosts({
                clientId,
                hostSuffixes: config.hostSuffixes,
                rootClientId: config.rootClientId,
            });
            const allowedHosts = new Set(allowedHostList);
            if (allowedHosts.size === 0) {
                throw new ValidationError(
                    `no allowed redirect hosts configured for app ${JSON.stringify(clientId)} ` +
                        `(set REDIRECT_HOST_SUFFIXES)`,
                );
            }

            const body = req.body as RegisterRequestBody;
            const uriOpts = { clientId, allowedHosts, max: config.maxRedirectUris };

            // Two ways in, and `callback_path` wins when both are present.
            //
            // A caller that wants the registrar-authoritative host set cannot know
            // in advance whether it is talking to a registrar old enough to ignore
            // `callback_path`, so during a rollout it sends BOTH: the path for us,
            // and its own best-guess `redirect_uris` so an older registrar still
            // answers. That combination must not be an error, and here the path
            // must be the one that counts — otherwise the caller's guess (which is
            // exactly what gets the bare root hostname wrong) would win.
            const redirectUris =
                body?.callback_path !== undefined
                    ? deriveRedirectUris(allowedHostList, body.callback_path, uriOpts)
                    : validateSubmittedRedirectUris(body?.redirect_uris, uriOpts);

            // Logout wiring. Both optional and independent: an AppShield old
            // enough to send neither registers exactly as it always did, and a
            // half-configured one still gets whichever half it asked for.
            //
            // post_logout_redirect_uris reuses deriveRedirectUris — same hosts,
            // same validation — because it IS a browser redirect target and must
            // be governed by the same invariant as the callback. Dex refuses any
            // post_logout_redirect_uri not in this list.
            const postLogoutRedirectUris =
                body?.post_logout_path !== undefined
                    ? deriveRedirectUris(allowedHostList, body.post_logout_path, uriOpts)
                    : undefined;
            const backchannelLogoutUri =
                body?.backchannel_logout_path !== undefined
                    ? deriveBackchannelUri(clientId, body.backchannel_logout_path)
                    : undefined;

            const { clientSecret } = await registrar.register(clientId, redirectUris, {
                postLogoutRedirectUris,
                backchannelLogoutUri,
            });

            console.log(
                `[registrar] registered client_id=${clientId} redirects=${redirectUris.length} ` +
                    `post_logout=${postLogoutRedirectUris?.length ?? 0} ` +
                    `backchannel=${backchannelLogoutUri ? "yes" : "no"} source=${sourceIp}`,
            );
            res.status(200).json({
                client_id: clientId,
                client_secret: clientSecret,
                issuer_url: config.issuerUrl,
                // The authoritative list, echoed so the caller can adopt it instead
                // of recomputing `<app>-<suffix>` on its own. A caller that derives
                // its own host set has no way to know about the bare root hostname,
                // which is not a function of its name.
                redirect_uris: redirectUris,
                // Echoed for the same reason as redirect_uris: the caller cannot
                // derive the authoritative host set itself.
                post_logout_redirect_uris: postLogoutRedirectUris,
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
