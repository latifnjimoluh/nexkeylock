export type Categorie = "tout" | "connexion" | "note" | "secret";

interface Proprietes {
  categorie: Categorie;
  onCategorie: (c: Categorie) => void;
}

const ELEMENTS: { cle: Categorie; libelle: string; icone: string }[] = [
  { cle: "tout", libelle: "Tout", icone: "📁" },
  { cle: "connexion", libelle: "Connexions", icone: "🔑" },
  { cle: "note", libelle: "Notes", icone: "📝" },
  { cle: "secret", libelle: "Secrets", icone: "🗝" },
];

// Sections planifiées (jalons ultérieurs), affichées désactivées par honnêteté.
const A_VENIR = [
  { libelle: "Tableau de bord", icone: "📊", jalon: "F6" },
  { libelle: "Réglages", icone: "⚙", jalon: "F7" },
];

/** Navigation latérale par catégorie (deviendra un tiroir/onglets sur mobile). */
export function BarreLaterale({ categorie, onCategorie }: Proprietes) {
  return (
    <nav className="flex h-full flex-col gap-1 border-r border-bordure bg-surface p-3" aria-label="Catégories">
      {ELEMENTS.map((e) => (
        <button
          key={e.cle}
          type="button"
          onClick={() => onCategorie(e.cle)}
          aria-current={categorie === e.cle}
          className={`flex items-center gap-3 rounded-jeton px-3 py-2 text-left text-sm transition ${
            categorie === e.cle
              ? "bg-accent/15 font-medium text-texte"
              : "text-texte-doux hover:bg-surface-haute hover:text-texte"
          }`}
        >
          <span aria-hidden>{e.icone}</span>
          {e.libelle}
        </button>
      ))}
      <div className="my-2 border-t border-bordure" />
      {A_VENIR.map((e) => (
        <span
          key={e.libelle}
          className="flex cursor-not-allowed items-center gap-3 rounded-jeton px-3 py-2 text-left text-sm text-texte-doux/50"
          title={`Disponible au jalon ${e.jalon}`}
        >
          <span aria-hidden>{e.icone}</span>
          {e.libelle}
        </span>
      ))}
    </nav>
  );
}
