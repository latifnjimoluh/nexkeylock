import { useEffect, useState } from "react";
import { JaugeScore } from "../composants/JaugeScore";
import { Bouton } from "../composants/Bouton";
import {
  lancerAudit,
  verifierFuites,
  type RapportAudit,
  type ElementAudit,
  type ElementFuite,
} from "../lib/pont";

interface Proprietes {
  onOuvrirEntree: (id: string) => void;
  onToast: (message: string) => void;
}

/** Tableau de bord de sécurité : audit local + vérification de fuites opt-in. */
export function EcranTableauBord({ onOuvrirEntree, onToast }: Proprietes) {
  const [rapport, setRapport] = useState<RapportAudit | null>(null);
  const [fuites, setFuites] = useState<ElementFuite[] | null>(null);
  const [verifEnCours, setVerifEnCours] = useState(false);

  useEffect(() => {
    lancerAudit()
      .then(setRapport)
      .catch(() => onToast("Audit impossible."));
  }, [onToast]);

  const verifier = async () => {
    setVerifEnCours(true);
    try {
      setFuites(await verifierFuites());
    } catch {
      onToast("Vérification de fuites indisponible (hors ligne ?).");
    } finally {
      setVerifEnCours(false);
    }
  };

  if (!rapport) {
    return <p className="p-8 text-center text-texte-doux">Analyse en cours…</p>;
  }

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-8">
      <h1 className="text-xl font-semibold text-texte">Tableau de bord de sécurité</h1>

      <section className="flex items-center gap-6 rounded-jeton border border-bordure bg-surface p-6">
        <JaugeScore score={rapport.score} />
        <div>
          <p className="text-texte">Score de santé du coffre</p>
          <p className="text-sm text-texte-doux">
            Calculé localement sur {rapport.totalAvecMotDePasse} entrée(s) avec mot de passe.
          </p>
        </div>
      </section>

      <div className="grid gap-4 sm:grid-cols-3">
        <CarteAudit
          titre="Faibles"
          elements={rapport.faibles}
          couleur="text-danger"
          onOuvrir={onOuvrirEntree}
        />
        <CarteAudit
          titre="Réutilisés"
          elements={rapport.reutilises}
          couleur="text-alerte"
          onOuvrir={onOuvrirEntree}
        />
        <CarteAudit
          titre="Anciens (>1 an)"
          elements={rapport.anciens}
          couleur="text-texte-doux"
          onOuvrir={onOuvrirEntree}
        />
      </div>

      <section className="rounded-jeton border border-bordure bg-surface p-6">
        <div className="mb-2 flex items-center justify-between gap-2">
          <div>
            <h2 className="font-medium text-texte">Mots de passe compromis</h2>
            <p className="text-sm text-texte-doux">
              Vérification en ligne (k-anonymat) : seul un préfixe de hachage est envoyé.
            </p>
          </div>
          <Bouton onClick={() => void verifier()} disabled={verifEnCours}>
            {verifEnCours ? "Vérification…" : "Vérifier les fuites"}
          </Bouton>
        </div>
        {fuites !== null &&
          (fuites.length === 0 ? (
            <p className="text-sm text-succes">Aucune fuite connue pour vos mots de passe. 🎉</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {fuites.map((f) => (
                <li key={f.id}>
                  <button
                    type="button"
                    onClick={() => onOuvrirEntree(f.id)}
                    className="flex w-full items-center justify-between rounded-jeton px-2 py-1 text-left text-sm hover:bg-surface-haute"
                  >
                    <span className="text-texte">{f.nom}</span>
                    <span className="text-danger">
                      {f.occurrences.toLocaleString("fr-FR")} fuites
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ))}
      </section>
    </main>
  );
}

function CarteAudit({
  titre,
  elements,
  couleur,
  onOuvrir,
}: {
  titre: string;
  elements: ElementAudit[];
  couleur: string;
  onOuvrir: (id: string) => void;
}) {
  return (
    <div className="rounded-jeton border border-bordure bg-surface p-4">
      <div className="mb-2 flex items-baseline justify-between">
        <span className="text-sm text-texte-doux">{titre}</span>
        <span className={`text-2xl font-semibold ${couleur}`}>{elements.length}</span>
      </div>
      <ul className="flex flex-col gap-0.5">
        {elements.slice(0, 8).map((e) => (
          <li key={e.id}>
            <button
              type="button"
              onClick={() => onOuvrir(e.id)}
              className="w-full truncate rounded px-1 text-left text-sm text-texte hover:bg-surface-haute"
            >
              {e.nom}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
