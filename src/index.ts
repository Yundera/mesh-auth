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
});
