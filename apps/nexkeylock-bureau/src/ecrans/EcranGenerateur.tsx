import { GenerateurMotDePasse } from "../composants/GenerateurMotDePasse";
import { copierTexte } from "../lib/pont";

interface Proprietes {
  onToast: (message: string) => void;
  /** Délai d'effacement du presse-papiers (s), issu des réglages. */
  delaiCopie: number;
}

/** Écran autonome de génération de mots de passe / phrases de passe. */
export function EcranGenerateur({ onToast, delaiCopie }: Proprietes) {
  const copier = async (valeur: string) => {
    try {
      await copierTexte(valeur, delaiCopie);
      onToast(`Copié — effacement dans ${delaiCopie} s.`);
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
