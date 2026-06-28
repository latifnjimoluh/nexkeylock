/**
 * Pont vers le backend Tauri (couche de commandes).
 *
 * Toute la logique sensible vit côté Rust ; ce module ne fait qu'invoquer les
 * commandes et typer leurs résultats. Aucun secret n'est mis en cache ici.
 */
import { invoke } from "@tauri-apps/api/core";

/** Métadonnées renvoyées par le backend (jamais de secret). */
export interface Apercu {
  verrouille: boolean;
  existe: boolean;
  nombreEntrees: number;
  aRecuperation: boolean;
}

/** Erreur structurée renvoyée par une commande. */
export interface ErreurCommande {
  code: string;
  message: string;
}

/** Vrai si l'objet ressemble à une ErreurCommande. */
export function estErreurCommande(e: unknown): e is ErreurCommande {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

// Le backend sérialise en snake_case ; on normalise vers camelCase.
interface ApercuBrut {
  verrouille: boolean;
  existe: boolean;
  nombre_entrees: number;
  a_recuperation: boolean;
}

function normaliser(a: ApercuBrut): Apercu {
  return {
    verrouille: a.verrouille,
    existe: a.existe,
    nombreEntrees: a.nombre_entrees,
    aRecuperation: a.a_recuperation,
  };
}

/** Version du cœur (nex-coffre). */
export function versionCoeur(): Promise<string> {
  return invoke<string>("version_coeur");
}

/** Indique si un fichier de coffre existe déjà. */
export function coffreExiste(): Promise<boolean> {
  return invoke<boolean>("coffre_existe");
}

/** État courant (métadonnées). */
export async function etat(): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("etat"));
}

/** Crée un nouveau coffre (laisse le coffre déverrouillé). */
export async function creerCoffre(motDePasse: string): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("creer_coffre", { motDePasse }));
}

/** Déverrouille le coffre avec le mot de passe maître. */
export async function deverrouiller(motDePasse: string): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("deverrouiller", { motDePasse }));
}

/** Verrouille le coffre (efface les clés côté backend). */
export async function verrouiller(): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("verrouiller"));
}

/** Configure un code de récupération et le renvoie (à afficher une seule fois). */
export function configurerRecuperation(): Promise<string> {
  return invoke<string>("configurer_recuperation");
}
