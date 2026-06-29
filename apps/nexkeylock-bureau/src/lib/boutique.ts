/**
 * État applicatif minimal (Zustand). **Aucun secret** n'y réside : uniquement
 * l'aperçu (métadonnées) renvoyé par le backend. Le mot de passe maître n'est
 * jamais stocké ici ; il transite seulement le temps d'un appel de commande.
 */
import { create } from "zustand";
import * as pont from "./pont";

interface Boutique {
  apercu: pont.Apercu | null;
  pret: boolean;
  /** Charge l'état initial depuis le backend. */
  charger: () => Promise<void>;
  /** Crée un coffre (avec fichier-clé optionnel) ; le laisse déverrouillé. */
  creer: (motDePasse: string, cheminFichierCle?: string) => Promise<void>;
  /** Déverrouille le coffre (avec fichier-clé optionnel). */
  deverrouiller: (motDePasse: string, cheminFichierCle?: string) => Promise<void>;
  /** Verrouille le coffre. */
  verrouiller: () => Promise<void>;
}

export const useBoutique = create<Boutique>((set) => ({
  apercu: null,
  pret: false,
  charger: async () => {
    const apercu = await pont.etat();
    set({ apercu, pret: true });
  },
  creer: async (motDePasse, cheminFichierCle) => {
    set({ apercu: await pont.creerCoffre(motDePasse, cheminFichierCle) });
  },
  deverrouiller: async (motDePasse, cheminFichierCle) => {
    set({ apercu: await pont.deverrouiller(motDePasse, cheminFichierCle) });
  },
  verrouiller: async () => {
    set({ apercu: await pont.verrouiller() });
  },
}));
