/// <reference lib="webworker" />
/**
 * Web Worker hébergeant le cœur Rust (WASM).
 *
 * Le coffre déverrouillé (DEK + contenu) vit **ici**, hors du thread principal :
 * Argon2id ne gèle pas l'UI, et les secrets ne transitent jamais par le thread
 * UI sauf à la demande explicite (révélation d'un champ). RPC par messages.
 */
import init, { CoffrePwa, generer, fichier_cle_requis, hash_auth } from "../coeur-wasm/nex_wasm.js";

let chargement: Promise<void> | null = null;
let coffre: CoffrePwa | null = null;

function assurerWasm(): Promise<void> {
  if (!chargement) chargement = init().then(() => undefined);
  return chargement;
}

function exigerCoffre(): CoffrePwa {
  if (!coffre) throw "coffre verrouillé";
  return coffre;
}

const handlers: Record<string, (args: unknown[]) => unknown> = {
  creer: ([mdp, kf]) => {
    coffre = CoffrePwa.creer(mdp as string, kf as Uint8Array | undefined);
    return coffre.octets();
  },
  ouvrir: ([octets, mdp, kf]) => {
    coffre = CoffrePwa.ouvrir(octets as Uint8Array, mdp as string, kf as Uint8Array | undefined);
  },
  verrouiller: () => {
    coffre = null;
  },
  lister: () => exigerCoffre().lister(),
  reveler: ([id, champ]) => exigerCoffre().reveler(id as string, champ as string),
  ajouter: ([json, maintenant]) => {
    const c = exigerCoffre();
    c.ajouter(json as string, BigInt(maintenant as number));
    return c.octets();
  },
  octets: () => exigerCoffre().octets(),
  fichierCleRequis: ([octets]) => fichier_cle_requis(octets as Uint8Array),
  hashAuth: ([email, mdp]) => hash_auth(email as string, mdp as string),
  generer: ([longueur, symboles]) => generer(longueur as number, symboles as boolean),
};

self.onmessage = async (ev: MessageEvent) => {
  const { id, methode, args } = ev.data as { id: number; methode: string; args: unknown[] };
  try {
    await assurerWasm();
    const handler = handlers[methode];
    if (!handler) throw "méthode inconnue";
    const valeur = handler(args);
    self.postMessage({ id, ok: true, valeur });
  } catch (e) {
    self.postMessage({ id, ok: false, erreur: typeof e === "string" ? e : "erreur du cœur WASM" });
  }
};
