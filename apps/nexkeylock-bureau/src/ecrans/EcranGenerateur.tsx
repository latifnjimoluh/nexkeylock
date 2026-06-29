import { GenerateurMotDePasse } from "../composants/GenerateurMotDePasse";
import { copierTexte } from "../lib/pont";

/** Délai d'effacement du presse-papiers (s). Configurable au Jalon F7. */
const DELAI_COPIE = 20;

interface Proprietes {
  onToast: (message: string) => void;
}

/** Écran autonome de génération de mots de passe / phrases de passe. */
export function EcranGenerateur({ onToast }: Proprietes) {
  const copier = async (valeur: string) => {
    try {
      await copierTexte(valeur, DELAI_COPIE);
      onToast(`Copié — effacement dans ${DELAI_COPIE} s.`);
    } catch {
      onToast("Copie impossible.");
    }
  };

  return (
    <main className="mx-auto flex w-full max-w-xl flex-col gap-4 p-8">
      <div>
        <h1 className="text-xl font-semibold text-texte">Générateur</h1>
        <p className="text-sm text-texte-doux">
          Mots de passe et phrases de passe générés localement (CSPRNG du système).
        </p>
      </div>
      <GenerateurMotDePasse onCopier={(v) => void copier(v)} />
    </main>
  );
}
