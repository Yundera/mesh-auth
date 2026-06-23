// Copies non-TS runtime assets (.proto) from src/ to dist/ after tsc, since
// `tsc` only emits compiled JS. Run as the build step after tsc.
import { cpSync, statSync } from "node:fs";

cpSync("src", "dist", {
    recursive: true,
    // Recurse into directories; copy only .proto files (tsc handles the rest).
    filter: (src) => statSync(src).isDirectory() || src.endsWith(".proto"),
});

console.log("[build] copied .proto assets to dist/");
