/**
 * Pont vers le cœur Rust compilé en **WebAssembly**.
 *
 * Toute la cryptographie vit dans le WASM (cœur audité) ; ce module se contente
 * de charger le module et de réexporter l'API. **Aucune crypto en JS.**
 */
import init, { CoffrePwa, generer, fichier_cle_requis } from "../coeur-wasm/nex_wasm.js";

let chargement: Promise<void> | null = null;

/** Charge le module WASM (idempotent). À appeler avant toute opération. */
export function initialiserWasm(): Promise<void> {
  if (!chargement) {
    chargement = init().then(() => undefined);
  }
  return chargement;
}

export { CoffrePwa, generer, fichier_cle_requis };
