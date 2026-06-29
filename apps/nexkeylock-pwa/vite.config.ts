/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

// PWA installable (iPhone/Android/PC) servant le cœur Rust compilé en WASM.
export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      manifest: {
        name: "NexKeyLock",
        short_name: "NexKeyLock",
        description: "Gestionnaire de mots de passe zéro-connaissance",
        theme_color: "#0f1218",
        background_color: "#0f1218",
        display: "standalone",
        lang: "fr",
        icons: [
          { src: "icone-192.png", sizes: "192x192", type: "image/png" },
          { src: "icone-512.png", sizes: "512x512", type: "image/png" },
        ],
      },
      workbox: {
        // Met en cache l'app (y compris le .wasm) pour un fonctionnement hors-ligne.
        globPatterns: ["**/*.{js,css,html,wasm,png,svg}"],
      },
    }),
  ],
  server: {
    port: 1430,
    strictPort: true,
    // En dev, /sync est relayé vers le serveur de synchro local (même origine
    // côté navigateur → CSP stricte). En prod, un reverse-proxy fait de même.
    proxy: {
      "/sync": {
        target: "http://localhost:8787",
        changeOrigin: true,
        rewrite: (chemin) => chemin.replace(/^\/sync/, ""),
      },
    },
  },
  build: { target: "esnext", sourcemap: false },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/tests/configuration.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
