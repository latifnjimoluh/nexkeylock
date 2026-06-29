import { useEffect, useMemo, useState } from "react";
import { SelecteurTheme } from "../composants/SelecteurTheme";
import { Bouton } from "../composants/Bouton";
import { BarreLaterale, type Categorie } from "../composants/BarreLaterale";
import { ListeEntrees } from "../composants/ListeEntrees";
import { PanneauDetail } from "../composants/PanneauDetail";
import { Toast } from "../composants/Toast";
import { useBoutique } from "../lib/boutique";
import { listerEntrees, type EntreeApercu } from "../lib/pont";

/** Vue principale : barre latérale, liste recherchable, panneau de détail. */
export function EcranCoffre() {
  const verrouiller = useBoutique((b) => b.verrouiller);

  const [categorie, setCategorie] = useState<Categorie>("tout");
  const [recherche, setRecherche] = useState("");
  const [entrees, setEntrees] = useState<EntreeApercu[]>([]);
  const [chargement, setChargement] = useState(true);
  const [idSelectionne, setIdSelectionne] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    let actif = true;
    setChargement(true);
    listerEntrees(recherche)
      .then((liste) => {
        if (actif) setEntrees(liste);
      })
      .finally(() => {
        if (actif) setChargement(false);
      });
    return () => {
      actif = false;
    };
  }, [recherche]);

  const filtrees = useMemo(
    () => (categorie === "tout" ? entrees : entrees.filter((e) => e.categorie === categorie)),
    [entrees, categorie],
  );

  const selection = filtrees.find((e) => e.id === idSelectionne) ?? null;

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-bordure px-4 py-2">
        <span className="font-semibold">NexKeyLock</span>
        <div className="flex items-center gap-2">
          <SelecteurTheme />
          <Bouton variante="secondaire" onClick={() => void verrouiller()}>
            Verrouiller
          </Bouton>
        </div>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-[auto_minmax(0,1fr)] md:grid-cols-[14rem_22rem_minmax(0,1fr)]">
        <div className="hidden md:block">
          <BarreLaterale categorie={categorie} onCategorie={setCategorie} />
        </div>

        <div className="min-h-0 border-r border-bordure">
          <ListeEntrees
            entrees={filtrees}
            recherche={recherche}
            onRecherche={setRecherche}
            idSelectionne={idSelectionne}
            onSelection={setIdSelectionne}
            chargement={chargement}
          />
        </div>

        <div className="hidden min-h-0 md:block">
          {selection ? (
            <PanneauDetail entree={selection} onToast={setToast} />
          ) : (
            <div className="flex h-full items-center justify-center p-8 text-center text-texte-doux">
              Sélectionnez une entrée pour afficher ses détails.
            </div>
          )}
        </div>
      </div>

      {toast && <Toast message={toast} onFermer={() => setToast(null)} />}
    </div>
  );
}
