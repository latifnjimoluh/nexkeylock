import type { EntreeApercu } from "../lib/pont";

interface Proprietes {
  entree: EntreeApercu;
  selectionnee: boolean;
  onClick: () => void;
}

const ICONE: Record<string, string> = {
  connexion: "🔑",
  note: "📝",
  secret: "🗝",
  autre: "•",
};

/**
 * Une ligne de la liste. Toutes les valeurs (nom, utilisateur) sont rendues par
 * React **comme du texte** : une charge utile HTML/script reste inerte.
 */
export function CarteEntree({ entree, selectionnee, onClick }: Proprietes) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={selectionnee}
      className={`flex w-full items-center gap-3 rounded-jeton px-3 py-2 text-left transition ${
        selectionnee ? "bg-accent/15 ring-1 ring-accent" : "hover:bg-surface-haute"
      }`}
    >
      <span aria-hidden className="text-lg">
        {ICONE[entree.categorie] ?? ICONE.autre}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium text-texte">{entree.nom}</span>
        {entree.nomUtilisateur && (
          <span className="block truncate text-sm text-texte-doux">{entree.nomUtilisateur}</span>
        )}
      </span>
      {entree.aTotp && <span className="text-xs text-texte-doux">TOTP</span>}
    </button>
  );
}
