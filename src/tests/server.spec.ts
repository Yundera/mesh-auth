import { expect } from "chai";
import http from "node:http";
import { AddressInfo } from "node:net";
import { Attestor } from "../attestation.js";
import { Config } from "../config.js";
import { Registrar, RegistrationResult } from "../registration.js";
import { buildServer } from "../server.js";

class StubAttestor implements Attestor {
    constructor(private readonly name: string | Error) {}
    async resolveContainerName(_ip: string): Promise<string> {
        if (this.name instanceof Error) throw this.name;
        return this.name;
    }
}

class StubRegistrar implements Registrar {
    public calls: Array<{ clientId: string; redirectUris: string[] }> = [];
    constructor(private readonly result: RegistrationResult) {}
    async register(clientId: string, redirectUris: string[]): Promise<RegistrationResult> {
        this.calls.push({ clientId, redirectUris });
        return this.result;
    }
}

const baseConfig: Config = {
    port: 0,
    issuerUrl: "https://auth-test.local",
    backend: "authelia",
    scriptPath: "/dev/null",
    dexGrpcAddr: "dex:5557",
    dexClientsDir: "/tmp/dex-clients",
    dnsResolver: "127.0.0.11",
    maxRedirectUris: 10,
    hostSuffixes: ["alice.nsl.sh", "203-0-113-10.nip.io", "203-0-113-10.sslip.io"],
    rootClientId: "",
};

interface TestServer {
    url: string;
    close(): Promise<void>;
}

async function start(deps: { attestor: Attestor; registrar: Registrar; config?: Partial<Config> }): Promise<TestServer> {
    const app = buildServer({
        config: { ...baseConfig, ...(deps.config ?? {}) },
        attestor: deps.attestor,
        registrar: deps.registrar,
    });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    return {
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(() => r())),
    };
}

async function postJson(url: string, body: unknown): Promise<{ status: number; body: any }> {
    const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
}

describe("server /register", () => {
    it("happy path: derives client_id from attestor, delegates to registrar, returns issuer", async () => {
        const reg = new StubRegistrar({ clientSecret: "abcd1234" });
        const srv = await start({
            attestor: new StubAttestor("myapp"),
            registrar: reg,
        });
        try {
            const { status, body } = await postJson(`${srv.url}/register`, {
                redirect_uris: ["https://myapp-alice.nsl.sh/cb"],
            });
            expect(status).to.equal(200);
            expect(body).to.deep.equal({
                client_id: "myapp",
                client_secret: "abcd1234",
                issuer_url: "https://auth-test.local",
                redirect_uris: ["https://myapp-alice.nsl.sh/cb"],
            });
            expect(reg.calls).to.have.length(1);
            expect(reg.calls[0].clientId).to.equal("myapp");
            expect(reg.calls[0].redirectUris).to.deep.equal(["https://myapp-alice.nsl.sh/cb"]);
        } finally {
            await srv.close();
        }
    });

    it("rejects redirect URI outside caller's subdomain", async () => {
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({
            attestor: new StubAttestor("myapp"),
            registrar: reg,
        });
        try {
            const { status, body } = await postJson(`${srv.url}/register`, {
                redirect_uris: ["https://otherapp-alice.nsl.sh/cb"],
            });
            expect(status).to.equal(400);
            expect(body.error).to.match(/not allowed for app/);
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });

    it("rejects empty redirect_uris", async () => {
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({
            attestor: new StubAttestor("myapp"),
            registrar: reg,
        });
        try {
            const { status } = await postJson(`${srv.url}/register`, { redirect_uris: [] });
            expect(status).to.equal(400);
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });

    it("rejects more than max redirect URIs", async () => {
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({
            attestor: new StubAttestor("myapp"),
            registrar: reg,
            config: { maxRedirectUris: 2 },
        });
        try {
            const { status } = await postJson(`${srv.url}/register`, {
                redirect_uris: [
                    "https://myapp-a.nsl.sh/cb",
                    "https://myapp-b.nsl.sh/cb",
                    "https://myapp-c.nsl.sh/cb",
                ],
            });
            expect(status).to.equal(400);
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });

    it("surfaces attestation failure as 403", async () => {
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({
            attestor: new StubAttestor(new (await import("../attestation.js")).AttestationError("no PTR")),
            registrar: reg,
        });
        try {
            const { status, body } = await postJson(`${srv.url}/register`, {
                redirect_uris: ["https://myapp.nsl.sh/cb"],
            });
            expect(status).to.equal(403);
            expect(body.error).to.match(/attestation/);
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });

    it("rejects PTR result that isn't a valid container name", async () => {
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({
            attestor: new StubAttestor("Bad Name!"),
            registrar: reg,
        });
        try {
            const { status } = await postJson(`${srv.url}/register`, {
                redirect_uris: ["https://myapp.nsl.sh/cb"],
            });
            expect(status).to.equal(400);
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });
});

describe("server /register with callback_path (registrar-authoritative)", () => {
    it("derives one redirect URI per allowed host and echoes the list back", async () => {
        const reg = new StubRegistrar({ clientSecret: "s3cret" });
        const srv = await start({ attestor: new StubAttestor("myapp"), registrar: reg });
        try {
            const { status, body } = await postJson(`${srv.url}/register`, {
                callback_path: "/nhl-auth/oidc/callback",
            });
            expect(status).to.equal(200);
            expect(body.redirect_uris).to.deep.equal([
                "https://myapp-alice.nsl.sh/nhl-auth/oidc/callback",
                "https://myapp-203-0-113-10.nip.io/nhl-auth/oidc/callback",
                "https://myapp-203-0-113-10.sslip.io/nhl-auth/oidc/callback",
            ]);
            expect(reg.calls[0].redirectUris).to.deep.equal(body.redirect_uris);
        } finally {
            await srv.close();
        }
    });

    it("gives the root app the bare hostnames too, appended last", async () => {
        const reg = new StubRegistrar({ clientSecret: "s3cret" });
        const srv = await start({
            attestor: new StubAttestor("maison"),
            registrar: reg,
            config: { rootClientId: "maison" },
        });
        try {
            const { status, body } = await postJson(`${srv.url}/register`, {
                callback_path: "/nhl-auth/oidc/callback",
            });
            expect(status).to.equal(200);
            expect(body.redirect_uris).to.deep.equal([
                "https://maison-alice.nsl.sh/nhl-auth/oidc/callback",
                "https://maison-203-0-113-10.nip.io/nhl-auth/oidc/callback",
                "https://maison-203-0-113-10.sslip.io/nhl-auth/oidc/callback",
                "https://alice.nsl.sh/nhl-auth/oidc/callback",
                "https://203-0-113-10.nip.io/nhl-auth/oidc/callback",
                "https://203-0-113-10.sslip.io/nhl-auth/oidc/callback",
            ]);
        } finally {
            await srv.close();
        }
    });

    it("withholds the bare hostnames from an app that is not the root app", async () => {
        const reg = new StubRegistrar({ clientSecret: "s3cret" });
        const srv = await start({
            attestor: new StubAttestor("beacon"),
            registrar: reg,
            config: { rootClientId: "maison" },
        });
        try {
            const { body } = await postJson(`${srv.url}/register`, { callback_path: "/cb" });
            expect(body.redirect_uris).to.deep.equal([
                "https://beacon-alice.nsl.sh/cb",
                "https://beacon-203-0-113-10.nip.io/cb",
                "https://beacon-203-0-113-10.sslip.io/cb",
            ]);
        } finally {
            await srv.close();
        }
    });

    it("rejects an explicit bare-host redirect_uri from a non-root app", async () => {
        // The bare hostname is not claimable by asking, on either code path.
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({
            attestor: new StubAttestor("beacon"),
            registrar: reg,
            config: { rootClientId: "maison" },
        });
        try {
            const { status } = await postJson(`${srv.url}/register`, {
                redirect_uris: ["https://alice.nsl.sh/cb"],
            });
            expect(status).to.equal(400);
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });

    it("prefers callback_path when a transitional caller sends both", async () => {
        // A caller straddling registrar versions sends its own best-guess list so
        // an older registrar still answers. Ours must ignore that guess — it is
        // precisely the guess that misses the bare root hostname.
        const reg = new StubRegistrar({ clientSecret: "s3cret" });
        const srv = await start({
            attestor: new StubAttestor("maison"),
            registrar: reg,
            config: { rootClientId: "maison" },
        });
        try {
            const { status, body } = await postJson(`${srv.url}/register`, {
                callback_path: "/cb",
                redirect_uris: ["https://maison-alice.nsl.sh/cb"],
            });
            expect(status).to.equal(200);
            expect(body.redirect_uris).to.have.length(6);
            expect(body.redirect_uris).to.include("https://alice.nsl.sh/cb");
        } finally {
            await srv.close();
        }
    });

    it("rejects a malformed callback_path", async () => {
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({ attestor: new StubAttestor("myapp"), registrar: reg });
        try {
            for (const callback_path of ["cb", "https://evil.com/cb", "//evil.com/cb", "/cb#f", ""]) {
                const { status } = await postJson(`${srv.url}/register`, { callback_path });
                expect(status, `callback_path=${JSON.stringify(callback_path)}`).to.equal(400);
            }
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });

    it("rejects when the derived host set exceeds the redirect-URI cap", async () => {
        const reg = new StubRegistrar({ clientSecret: "unused" });
        const srv = await start({
            attestor: new StubAttestor("myapp"),
            registrar: reg,
            config: { maxRedirectUris: 2 },
        });
        try {
            const { status } = await postJson(`${srv.url}/register`, { callback_path: "/cb" });
            expect(status).to.equal(400);
            expect(reg.calls).to.have.length(0);
        } finally {
            await srv.close();
        }
    });
});

describe("server /health", () => {
    it("returns 200 ok", async () => {
        const srv = await start({
            attestor: new StubAttestor("unused"),
            registrar: new StubRegistrar({ clientSecret: "unused" }),
        });
        try {
            const res = await fetch(`${srv.url}/health`);
            expect(res.status).to.equal(200);
            expect(await res.json()).to.deep.equal({ status: "ok" });
        } finally {
            await srv.close();
        }
    });
});
