/**
 * Stockage local du coffre **chiffré** dans IndexedDB.
 *
 * On n'y range que le blob chiffré (le même format que le fichier `.vault`) ;
 * jamais le mot de passe maître ni de données en clair. La clé de déchiffrement
 * ne vit qu'en mémoire WASM le temps de la session.
 */
const BASE = "nexkeylock";
const MAGASIN = "coffre";
const CLE = "blob";

function ouvrir(): Promise<IDBDatabase> {
  return new Promise((resoudre, rejeter) => {
    const requete = indexedDB.open(BASE, 1);
    requete.onupgradeneeded = () => {
      requete.result.createObjectStore(MAGASIN);
    };
    requete.onsuccess = () => resoudre(requete.result);
    requete.onerror = () => rejeter(requete.error);
  });
}

/** Lit le blob chiffré du coffre, ou `null` s'il n'existe pas encore. */
export async function lireCoffre(): Promise<Uint8Array | null> {
  const db = await ouvrir();
  return new Promise((resoudre, rejeter) => {
    const tx = db.transaction(MAGASIN, "readonly");
    const req = tx.objectStore(MAGASIN).get(CLE);
    req.onsuccess = () => {
      const v = req.result as Uint8Array | undefined;
      resoudre(v ?? null);
    };
    req.onerror = () => rejeter(req.error);
  });
}

/** Écrit (remplace) le blob chiffré du coffre. */
export async function ecrireCoffre(octets: Uint8Array): Promise<void> {
  const db = await ouvrir();
  return new Promise((resoudre, rejeter) => {
    const tx = db.transaction(MAGASIN, "readwrite");
    tx.objectStore(MAGASIN).put(octets, CLE);
    tx.oncomplete = () => resoudre();
    tx.onerror = () => rejeter(tx.error);
  });
}

/** Indique si un coffre est présent localement. */
export async function coffreExiste(): Promise<boolean> {
  return (await lireCoffre()) !== null;
}
