import { readFileSync } from "node:fs";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig, loadEnv } from "vite";
import { resolveAppVersion } from "./src/lib/version.ts";

// Shown on the About page. `scripts/validate-release-config.py` keeps the package version equal to
// `Cargo.toml` and `tauri.conf.json`; release builds add the tag's label through
// `CONDUIT_RELEASE_VERSION`. The engine tag is the one pinned in the root `Cargo.toml`.
const packageVersion: string = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")).version;
const engineTag =
  /rusty-conduit-engine\s*=\s*\{[^}]*\btag\s*=\s*"([^"]+)"/.exec(
    readFileSync(new URL("../../Cargo.toml", import.meta.url), "utf8"),
  )?.[1] ?? "unknown";

export default defineConfig(({ mode }) => ({
  plugins: [svelte()],
  define: {
    __APP_VERSION__: JSON.stringify(
      resolveAppVersion(packageVersion, loadEnv(mode, ".", "CONDUIT_").CONDUIT_RELEASE_VERSION),
    ),
    __ENGINE_VERSION__: JSON.stringify(engineTag),
  },
  // Tauri serves the bundle from its own origin, so asset paths stay relative.
  base: "./",
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Oldest engines Tauri v2 runs on: WebKitGTK/WKWebView and WebView2.
    target: ["es2021", "safari15", "chrome105"],
  },
}));
