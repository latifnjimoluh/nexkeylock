/**
 * Client (thread principal) du cœur WASM hébergé dans un Web Worker.
 *
 * Toutes les opérations sont **asynchrones** (RPC). Le coffre déverrouillé reste
 * dans le worker ; le thread UI n'obtient que des métadonnées, ou un secret
 * précis à la demande (révélation), ou les octets chiffrés (stockage/synchro).
 */
const worker = new Worker(new URL("./coeur.worker.ts", import.meta.url), { type: "module" });

let prochainId = 1;
const enAttente = new Map<
  number,
  { resoudre: (v: unknown) => void; rejeter: (e: unknown) => void }
>();

worker.onmessage = (ev: MessageEvent) => {
  const r = ev.data as { id: number; ok: boolean; valeur?: unknown; erreur?: string };
  const p = enAttente.get(r.id);
  if (!p) return;
  enAttente.delete(r.id);
  if (r.ok) p.resoudre(r.valeur);
  else p.rejeter(r.erreur ?? "erreur");
};

function appel<T>(methode: string, ...args: unknown[]): Promise<T> {
  const id = prochainId++;
  return new Promise<T>((resoudre, rejeter) => {
    enAttente.set(id, { resoudre: resoudre as (v: unknown) => void, rejeter });
    worker.postMessage({ id, methode, args });
  });
}

export const coeur = {
  /** Crée un coffre ; renvoie ses octets chiffrés (à persister). */
  creer: (motDePasse: string, fichierCle?: Uint8Array) =>
    appel<Uint8Array>("creer", motDePasse, fichierCle),
  /** Ouvre un coffre depuis ses octets. */
  ouvrir: (octets: Uint8Array, motDePasse: string, fichierCle?: Uint8Array) =>
    appel<void>("ouvrir", octets, motDePasse, fichierCle),
  verrouiller: () => appel<void>("verrouiller"),
  lister: () => appel<string>("lister"),
  reveler: (id: string, champ: string) => appel<string>("reveler", id, champ),
  /** Ajoute une entrée ; renvoie les octets chiffrés à jour. */
  ajouter: (donneesJson: string, maintenant: number) =>
    appel<Uint8Array>("ajouter", donneesJson, maintenant),
  octets: () => appel<Uint8Array>("octets"),
  fichierCleRequis: (octets: Uint8Array) => appel<boolean>("fichierCleRequis", octets),
  hashAuth: (email: string, motDePasse: string) => appel<string>("hashAuth", email, motDePasse),
  generer: (longueur: number, symboles: boolean) => appel<string>("generer", longueur, symboles),
};
