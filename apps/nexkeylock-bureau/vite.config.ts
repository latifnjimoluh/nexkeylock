/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Configuration Vite + Tauri. Le serveur de dev est fixe (port 1420) car Tauri
// s'y connecte ; aucune ressource n'est servie depuis Internet.
export default defineConfig({
  plugins: [react()],
  // Tauri attend un port fixe et échoue si indisponible.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  // Variables d'environnement préfixées exposées au front.
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "esnext",
    // Pas de sourcemaps en production (ne pas exposer le code/commentaires).
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/tests/configuration.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
