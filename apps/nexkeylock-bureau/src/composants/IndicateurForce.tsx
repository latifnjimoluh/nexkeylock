import { estimerForce, libelleNiveau, type NiveauForce } from "../lib/force";

interface Proprietes {
  motDePasse: string;
}

const COULEUR: Record<NiveauForce, string> = {
  vide: "bg-bordure",
  faible: "bg-danger",
  moyen: "bg-alerte",
  bon: "bg-accent",
  excellent: "bg-succes",
};

const REMPLISSAGE: Record<NiveauForce, string> = {
  vide: "w-0",
  faible: "w-1/4",
  moyen: "w-2/4",
  bon: "w-3/4",
  excellent: "w-full",
};

/** Barre de force + entropie estimée d'un mot de passe (repère indicatif). */
export function IndicateurForce({ motDePasse }: Proprietes) {
  const { bits, niveau } = estimerForce(motDePasse);

  return (
    <div className="flex flex-col gap-1" aria-live="polite">
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-surface-haute"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={128}
        aria-valuenow={bits}
        aria-label="Force du mot de passe"
      >
        <div
          className={`h-full rounded-full transition-all ${COULEUR[niveau]} ${REMPLISSAGE[niveau]}`}
        />
      </div>
      <div className="flex justify-between text-xs text-texte-doux">
        <span>{libelleNiveau(niveau)}</span>
        <span>{bits > 0 ? `~${bits} bits` : ""}</span>
      </div>
    </div>
  );
}
