import { useEffect } from "react";
import { useBoutique } from "./lib/boutique";
import { EcranAccueil } from "./ecrans/EcranAccueil";
import { EcranVerrouillage } from "./ecrans/EcranVerrouillage";
import { EcranCoffre } from "./ecrans/EcranCoffre";

/** Routeur applicatif : choisit l'écran selon l'état du coffre. */
export function App() {
  const apercu = useBoutique((b) => b.apercu);
  const pret = useBoutique((b) => b.pret);
  const charger = useBoutique((b) => b.charger);

  useEffect(() => {
    void charger();
  }, [charger]);

  if (!pret || apercu === null) {
    return (
      <div className="flex min-h-full items-center justify-center text-texte-doux">Chargement…</div>
    );
  }

  if (!apercu.existe) return <EcranAccueil />;
  if (apercu.verrouille) return <EcranVerrouillage />;
  return <EcranCoffre />;
}
