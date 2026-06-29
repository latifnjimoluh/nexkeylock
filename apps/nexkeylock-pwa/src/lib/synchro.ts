/**
 * Client de **synchronisation zéro-connaissance** de la PWA.
 *
 * Appels en **même origine** vers `/sync/...` (proxy en dev, reverse-proxy en
 * prod) afin de garder la CSP stricte (`connect-src 'self'`). Le hash
 * d'authentification est dérivé **dans le WASM** (le mot de passe ne quitte pas
 * l'appareil) ; le blob poussé est le coffre **déjà chiffré**.
 */
import { coeur } from "./coeur";

const RACINE = "/sync";
const CLE_REVISION = "nexkeylock.sync.revision";
const CLE_EMAIL = "nexkeylock.sync.email";

let jeton: string | null = null;

/** Révision locale connue (concurrence optimiste). */
export function revisionLocale(): number {
  return Number(localStorage.getItem(CLE_REVISION) ?? "0");
}
function definirRevision(r: number) {
  localStorage.setItem(CLE_REVISION, String(r));
}
/** Email mémorisé (préférence, non secret). */
export function emailMemorise(): string {
  return localStorage.getItem(CLE_EMAIL) ?? "";
}
/** Vrai si une session de synchronisation est active. */
export function connecte(): boolean {
  return jeton !== null;
}

function versHex(octets: Uint8Array): string {
  return Array.from(octets, (o) => o.toString(16).padStart(2, "0")).join("");
}
function depuisHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function poster(chemin: string, corps: unknown, avecJeton = false): Promise<Response> {
  const entetes: Record<string, string> = { "Content-Type": "application/json" };
  if (avecJeton && jeton) entetes.Authorization = `Bearer ${jeton}`;
  return fetch(`${RACINE}${chemin}`, {
    method: "POST",
    headers: entetes,
    body: JSON.stringify(corps),
  });
}

/** Inscrit un compte (email + mot de passe maître). */
export async function inscrire(email: string, motDePasse: string): Promise<void> {
  const hash = await coeur.hashAuth(email, motDePasse);
  const rep = await poster("/inscription", { email, hash_auth: hash });
  if (rep.status === 409) throw "Un compte existe déjà pour cet email.";
  if (!rep.ok) throw "Inscription refusée par le serveur.";
}

/** Se connecte ; mémorise le jeton de session et l'email. */
export async function connecter(email: string, motDePasse: string): Promise<void> {
  const hash = await coeur.hashAuth(email, motDePasse);
  const rep = await poster("/connexion", { email, hash_auth: hash });
  if (!rep.ok) throw "Identifiants de synchronisation invalides.";
  const v = (await rep.json()) as { jeton?: string };
  if (!v.jeton) throw "Jeton absent de la réponse.";
  jeton = v.jeton;
  localStorage.setItem(CLE_EMAIL, email);
}

/** Tire le coffre distant ; renvoie (révision, octets) — octets vide si rien. */
export async function tirer(): Promise<{ revision: number; octets: Uint8Array }> {
  const rep = await fetch(`${RACINE}/coffre`, { headers: { Authorization: `Bearer ${jeton}` } });
  if (!rep.ok) throw "Session expirée ; reconnectez-vous.";
  const v = (await rep.json()) as { revision: number; blob: string };
  definirRevision(v.revision);
  return { revision: v.revision, octets: v.blob ? depuisHex(v.blob) : new Uint8Array() };
}

/** Pousse `octets` (coffre chiffré). `accepte=false` => conflit (révision distante). */
export async function pousser(octets: Uint8Array): Promise<{ accepte: boolean; revision: number }> {
  const rep = await poster("/coffre", { base: revisionLocale(), blob: versHex(octets) }, true);
  if (rep.status === 401) throw "Session expirée ; reconnectez-vous.";
  const v = (await rep.json()) as { revision?: number; actuelle?: number };
  if (rep.ok) {
    const revision = v.revision ?? 0;
    definirRevision(revision);
    return { accepte: true, revision };
  }
  // 409 : conflit.
  return { accepte: false, revision: v.actuelle ?? 0 };
}

/** Force l'envoi en écrasant le distant (résolution de conflit « garder local »). */
export async function forcer(octets: Uint8Array): Promise<{ accepte: boolean; revision: number }> {
  // S'aligne sur la révision distante courante, puis pousse.
  const distant = await tirer();
  definirRevision(distant.revision);
  return pousser(octets);
}
