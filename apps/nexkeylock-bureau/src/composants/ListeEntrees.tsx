import type { EntreeApercu } from "../lib/pont";
import { CarteEntree } from "./CarteEntree";

interface Proprietes {
  entrees: EntreeApercu[];
  recherche: string;
  onRecherche: (v: string) => void;
  idSelectionne: string | null;
  onSelection: (id: string) => void;
  chargement: boolean;
}

/** Colonne de recherche + liste des entrées (états vide/chargement gérés). */
export function ListeEntrees({
  entrees,
  recherche,
  onRecherche,
  idSelectionne,
  onSelection,
  chargement,
}: Proprietes) {
  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-bordure p-3">
        <input
          type="search"
          value={recherche}
          onChange={(e) => onRecherche(e.target.value)}
          placeholder="Rechercher…"
          aria-label="Rechercher une entrée"
          className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 text-texte placeholder:text-texte-doux"
        />
      </div>
      <div className="flex-1 overflow-y-auto p-2">
        {chargement ? (
          <p className="p-4 text-center text-sm text-texte-doux">Chargement…</p>
        ) : entrees.length === 0 ? (
          <p className="p-4 text-center text-sm text-texte-doux">
            {recherche ? "Aucun résultat." : "Aucune entrée pour l'instant."}
          </p>
        ) : (
          <ul className="flex flex-col gap-1">
            {entrees.map((e) => (
              <li key={e.id}>
                <CarteEntree
                  entree={e}
                  selectionnee={e.id === idSelectionne}
                  onClick={() => onSelection(e.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
