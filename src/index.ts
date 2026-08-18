import { DnsPtrAttestor } from "./attestation.js";
import { loadConfig } from "./config.js";
import { DexGrpcRegistrar } from "./registration.dex.js";
import { Registrar, ShellRegistrar } from "./registration.js";
import { buildServer } from "./server.js";

const config = loadConfig();
const attestor = new DnsPtrAttestor(config.dnsResolver);

// The Dex backend dials lazily (first RPC), so constructing it is side-effect
// free; with backend defaulting to "authelia" it is never constructed in prod
// until cutover.
const registrar: Registrar =
    config.backend === "dex"
        ? new DexGrpcRegistrar(config.dexGrpcAddr, config.dexClientsDir)
        : new ShellRegistrar(config.scriptPath);

const app = buildServer({ config, attestor, registrar });

app.listen(config.port, () => {
    const target = config.backend === "dex" ? `dex=${config.dexGrpcAddr}` : `script=${config.scriptPath}`;
    console.log(`[registrar] listening on :${config.port} backend=${config.backend} issuer=${config.issuerUrl} ${target}`);
    console.log(`[registrar] redirect host suffixes: ${config.hostSuffixes.join(", ") || "(none — all registrations rejected)"}`);
    // Stated explicitly because the failure mode of an unset/unusable value is a
    // working login that silently lands on the wrong hostname — the exact symptom
    // this setting exists to fix. "none" here is the first thing to check.
    console.log(`[registrar] root app (may claim the bare suffixes): ${config.rootClientId || "none"}`);
});
