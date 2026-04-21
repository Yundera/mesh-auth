import { DnsPtrAttestor } from "./attestation.js";
import { loadConfig } from "./config.js";
import { ShellRegistrar } from "./registration.js";
import { buildServer } from "./server.js";

const config = loadConfig();
const attestor = new DnsPtrAttestor(config.dnsResolver);
const registrar = new ShellRegistrar(config.scriptPath);

const app = buildServer({ config, attestor, registrar });

app.listen(config.port, () => {
    console.log(
        `[registrar] listening on :${config.port} issuer=${config.issuerUrl} script=${config.scriptPath}`,
    );
});
