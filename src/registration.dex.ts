import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { LogoutRegistration, Registrar, RegistrationError, RegistrationResult } from "./registration.js";

const moduleDir = dirname(fileURLToPath(import.meta.url));
// dist/registration.dex.js -> dist/dex/api.proto (copied from src by scripts/copy-assets.mjs)
const PROTO_PATH = join(moduleDir, "dex", "api.proto");

interface DexClient {
    id: string;
    secret: string;
    redirectUris: string[];
    name: string;
    public: boolean;
    // Logout wiring — Dex master only (no release carries these yet). Omitted
    // rather than sent empty when the caller supplies nothing, so an older Dex
    // sees exactly the message it saw before.
    backchannelLogoutUri?: string;
    postLogoutRedirectUris?: string[];
}

interface CreateClientResp {
    alreadyExists?: boolean;
    client?: DexClient;
}

interface NotFoundResp {
    notFound?: boolean;
}

type Cb<T> = (err: grpc.ServiceError | null, resp: T) => void;

interface DexUpdateReq {
    id: string;
    redirectUris: string[];
    name: string;
    backchannelLogoutUri?: string;
    postLogoutRedirectUris?: string[];
}

interface DexService {
    CreateClient(req: { client: DexClient }, cb: Cb<CreateClientResp>): void;
    UpdateClient(req: DexUpdateReq, cb: Cb<NotFoundResp>): void;
    DeleteClient(req: { id: string }, cb: Cb<NotFoundResp>): void;
}

function loadDexService(addr: string): DexService {
    const pkgDef = protoLoader.loadSync(PROTO_PATH, {
        keepCase: false, // camelCase JS fields: redirect_uris -> redirectUris
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const proto = grpc.loadPackageDefinition(pkgDef) as any;
    // Plaintext: Dex's gRPC API is unauthenticated and MUST be reachable only on
    // the internal `pcs` network (see SSO-DEX-MIGRATION-PLAN.md §8).
    return new proto.api.Dex(addr, grpc.credentials.createInsecure()) as DexService;
}

/**
 * Registers OIDC clients in Dex via its gRPC API, replacing the Authelia
 * shell-out. Keeps the /register contract identical: same {clientId,
 * redirectUris} in, {clientSecret} out.
 *
 * Idempotency: Dex's CreateClient returns {alreadyExists:true} WITHOUT echoing
 * the secret back (verified against v2.43.1), so the issued secret is persisted
 * locally under clientsDir and reused on reinstall — the equivalent of the
 * `clients.d/<id>.secret` files the shell registrar relied on.
 */
export class DexGrpcRegistrar implements Registrar {
    private readonly dex: DexService;

    constructor(
        private readonly grpcAddr: string,
        private readonly clientsDir: string,
    ) {
        this.dex = loadDexService(grpcAddr);
    }

    async register(
        clientId: string,
        redirectUris: string[],
        logout: LogoutRegistration = {},
    ): Promise<RegistrationResult> {
        if (redirectUris.length === 0) {
            throw new RegistrationError("at least one redirect URI is required");
        }

        const existing = await this.readSecret(clientId);
        const secret = existing ?? randomBytes(32).toString("hex");

        const resp = await this.createClient(clientId, secret, redirectUris, logout);

        if (!resp.alreadyExists) {
            await this.persistSecret(clientId, secret);
            return { clientSecret: secret };
        }

        // Client already exists in Dex.
        if (existing) {
            // We own the secret already; keep redirect URIs in sync (best-effort).
            //
            // THIS is the path that matters for the logout rollout: every gate
            // already registered before logout existed takes it, so UpdateClient
            // — not CreateClient — is what actually attaches the back-channel URI
            // to the fleet. Sending them only on create would leave every
            // existing client silently un-notified forever.
            await this.updateClient(clientId, redirectUris, logout).catch((err: unknown) => {
                console.warn(`[registrar] UpdateClient(${clientId}) failed: ${String(err)}`);
            });
            return { clientSecret: existing };
        }

        // Exists in Dex but the local secret was lost (Dex never echoes it back).
        // Recover by rotating: delete then recreate with a known secret.
        await this.deleteClient(clientId);
        const recreated = await this.createClient(clientId, secret, redirectUris, logout);
        if (recreated.alreadyExists) {
            throw new RegistrationError(`failed to recover client ${clientId}: still exists after delete`);
        }
        await this.persistSecret(clientId, secret);
        return { clientSecret: secret };
    }

    private createClient(
        id: string,
        secret: string,
        redirectUris: string[],
        logout: LogoutRegistration,
    ): Promise<CreateClientResp> {
        const client: DexClient = { id, secret, redirectUris, name: id, public: false };
        if (logout.backchannelLogoutUri) client.backchannelLogoutUri = logout.backchannelLogoutUri;
        if (logout.postLogoutRedirectUris?.length) {
            client.postLogoutRedirectUris = logout.postLogoutRedirectUris;
        }
        return new Promise((resolve, reject) => {
            this.dex.CreateClient({ client }, (err, resp) =>
                err ? reject(new RegistrationError(`Dex CreateClient failed: ${err.message}`)) : resolve(resp),
            );
        });
    }

    private updateClient(
        id: string,
        redirectUris: string[],
        logout: LogoutRegistration,
    ): Promise<void> {
        const req: DexUpdateReq = { id, redirectUris, name: id };
        if (logout.backchannelLogoutUri) req.backchannelLogoutUri = logout.backchannelLogoutUri;
        if (logout.postLogoutRedirectUris?.length) {
            req.postLogoutRedirectUris = logout.postLogoutRedirectUris;
        }
        return new Promise((resolve, reject) => {
            this.dex.UpdateClient(req, (err) =>
                err ? reject(new RegistrationError(`Dex UpdateClient failed: ${err.message}`)) : resolve(),
            );
        });
    }

    private deleteClient(id: string): Promise<void> {
        return new Promise((resolve, reject) => {
            this.dex.DeleteClient({ id }, (err) =>
                err ? reject(new RegistrationError(`Dex DeleteClient failed: ${err.message}`)) : resolve(),
            );
        });
    }

    private secretPath(clientId: string): string {
        return join(this.clientsDir, `${clientId}.secret`);
    }

    private async readSecret(clientId: string): Promise<string | undefined> {
        try {
            const s = (await readFile(this.secretPath(clientId), "utf8")).trim();
            return s.length > 0 ? s : undefined;
        } catch (err) {
            if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
                return undefined;
            }
            throw new RegistrationError(`failed to read stored secret for ${clientId}: ${String(err)}`);
        }
    }

    private async persistSecret(clientId: string, secret: string): Promise<void> {
        await mkdir(this.clientsDir, { recursive: true });
        await writeFile(this.secretPath(clientId), secret, { mode: 0o600 });
    }
}
