import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [svelte()],
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
});
