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
  /** Crée un coffre (le laisse déverrouillé). */
  creer: (motDePasse: string) => Promise<void>;
  /** Déverrouille le coffre. */
  deverrouiller: (motDePasse: string) => Promise<void>;
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
  creer: async (motDePasse) => {
    set({ apercu: await pont.creerCoffre(motDePasse) });
  },
  deverrouiller: async (motDePasse) => {
    set({ apercu: await pont.deverrouiller(motDePasse) });
  },
  verrouiller: async () => {
    set({ apercu: await pont.verrouiller() });
  },
}));
