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
    scriptPath: "/dev/null",
    redirectUriHostnameSuffix: undefined,
    dnsResolver: "127.0.0.11",
    maxRedirectUris: 10,
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
            expect(body.error).to.match(/first label/);
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
