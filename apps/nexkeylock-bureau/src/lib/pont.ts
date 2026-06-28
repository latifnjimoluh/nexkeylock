/**
 * Pont vers le backend Tauri (couche de commandes).
 *
 * Toute la logique sensible vit côté Rust ; ce module ne fait qu'invoquer les
 * commandes et typer leurs résultats. Aucun secret n'est mis en cache ici.
 */
import { invoke } from "@tauri-apps/api/core";

/** Version du cœur (nex-coffre) — commande de fumée pour valider le pont. */
export function versionCoeur(): Promise<string> {
  return invoke<string>("version_coeur");
}
