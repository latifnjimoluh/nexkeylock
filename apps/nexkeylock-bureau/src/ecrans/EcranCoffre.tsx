import { useEffect, useMemo, useState } from "react";
import { SelecteurTheme } from "../composants/SelecteurTheme";
import { Bouton } from "../composants/Bouton";
import { BarreLaterale, type Categorie } from "../composants/BarreLaterale";
import { ListeEntrees } from "../composants/ListeEntrees";
import { PanneauDetail } from "../composants/PanneauDetail";
import { FormulaireEntree } from "../composants/FormulaireEntree";
import { Modale } from "../composants/Modale";
import { Toast } from "../composants/Toast";
import { EcranGenerateur } from "./EcranGenerateur";
import { EcranTableauBord } from "./EcranTableauBord";
import { EcranReglages } from "./EcranReglages";
import { useBoutique } from "../lib/boutique";
import { useVerrouillageAuto } from "../lib/verrouillageAuto";
import { listerEntrees, obtenirReglages, supprimerEntree, type EntreeApercu } from "../lib/pont";

type Vue = "coffre" | "generateur" | "tableau" | "reglages";

/** Vue principale : barre latérale, liste recherchable, panneau de détail. */
export function EcranCoffre() {
  const verrouiller = useBoutique((b) => b.verrouiller);
  const charger = useBoutique((b) => b.charger);

  const [categorie, setCategorie] = useState<Categorie>("tout");
  const [recherche, setRecherche] = useState("");
  const [entrees, setEntrees] = useState<EntreeApercu[]>([]);
  const [chargement, setChargement] = useState(true);
  const [idSelectionne, setIdSelectionne] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [rechargement, setRechargement] = useState(0);
  const [vue, setVue] = useState<Vue>("coffre");
  const [delaiCopie, setDelaiCopie] = useState(20);
  const [delaiAutoLock, setDelaiAutoLock] = useState(5);

  useEffect(() => {
    obtenirReglages()
      .then((r) => {
        setDelaiCopie(r.delaiPressePapiersS);
        setDelaiAutoLock(r.delaiAutoLockMin);
      })
      .catch(() => undefined);
  }, []);

  // Verrouillage automatique (inactivité + minimisation) → efface les clés.
  useVerrouillageAuto(delaiAutoLock, () => void verrouiller(), true);

  // Formulaire (création/édition) et confirmation de suppression.
  const [formulaireOuvert, setFormulaireOuvert] = useState(false);
  const [formulaireInitiale, setFormulaireInitiale] = useState<EntreeApercu | null>(null);
  const [aSupprimer, setASupprimer] = useState<EntreeApercu | null>(null);

  useEffect(() => {
    let actif = true;
    setChargement(true);
    listerEntrees(recherche)
      .then((liste) => {
        if (actif) setEntrees(liste);
      })
      .catch(() => {
        if (actif) setEntrees([]);
      })
      .finally(() => {
        if (actif) setChargement(false);
      });
    return () => {
      actif = false;
    };
  }, [recherche, rechargement]);

  const recharger = () => setRechargement((n) => n + 1);

  const filtrees = useMemo(
    () => (categorie === "tout" ? entrees : entrees.filter((e) => e.categorie === categorie)),
    [entrees, categorie],
  );

  const selection = filtrees.find((e) => e.id === idSelectionne) ?? null;

  const ouvrirCreation = () => {
    setFormulaireInitiale(null);
    setFormulaireOuvert(true);
  };
  const ouvrirEdition = (e: EntreeApercu) => {
    setFormulaireInitiale(e);
    setFormulaireOuvert(true);
  };

  const confirmerSuppression = async () => {
    if (!aSupprimer) return;
    try {
      await supprimerEntree(aSupprimer.id);
      if (idSelectionne === aSupprimer.id) setIdSelectionne(null);
      setToast("Entrée supprimée.");
      recharger();
    } catch {
      setToast("Suppression impossible.");
    } finally {
      setASupprimer(null);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-bordure px-4 py-2">
        <span className="font-semibold">NexKeyLock</span>
        <div className="flex items-center gap-2">
          {vue === "coffre" ? (
            <>
              <Bouton onClick={ouvrirCreation}>+ Ajouter</Bouton>
              <Bouton variante="secondaire" onClick={() => setVue("tableau")}>
                Tableau
              </Bouton>
              <Bouton variante="secondaire" onClick={() => setVue("generateur")}>
                Générateur
              </Bouton>
              <Bouton variante="secondaire" onClick={() => setVue("reglages")}>
                Réglages
              </Bouton>
            </>
          ) : (
            <Bouton variante="secondaire" onClick={() => setVue("coffre")}>
              ← Coffre
            </Bouton>
          )}
          <SelecteurTheme />
          <Bouton variante="secondaire" onClick={() => void verrouiller()}>
            Verrouiller
          </Bouton>
        </div>
      </header>

      {vue === "generateur" ? (
        <div className="min-h-0 flex-1 overflow-y-auto">
          <EcranGenerateur onToast={setToast} delaiCopie={delaiCopie} />
        </div>
      ) : vue === "tableau" ? (
        <div className="min-h-0 flex-1 overflow-y-auto">
          <EcranTableauBord
            onToast={setToast}
            onOuvrirEntree={(id) => {
              setCategorie("tout");
              setIdSelectionne(id);
              setVue("coffre");
            }}
          />
        </div>
      ) : vue === "reglages" ? (
        <div className="min-h-0 flex-1 overflow-y-auto">
          <EcranReglages
            onToast={setToast}
            onCoffreChange={() => {
              void charger();
              setVue("coffre");
            }}
          />
        </div>
      ) : (
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
              <PanneauDetail
                entree={selection}
                onToast={setToast}
                onModifier={() => ouvrirEdition(selection)}
                onSupprimer={() => setASupprimer(selection)}
                delaiCopie={delaiCopie}
              />
            ) : (
              <div className="flex h-full items-center justify-center p-8 text-center text-texte-doux">
                Sélectionnez une entrée pour afficher ses détails.
              </div>
            )}
          </div>
        </div>
      )}

      {formulaireOuvert && (
        <FormulaireEntree
          initiale={formulaireInitiale}
          onFerme={() => setFormulaireOuvert(false)}
          onEnregistre={recharger}
        />
      )}

      {aSupprimer && (
        <Modale titre="Supprimer l'entrée" onFermer={() => setASupprimer(null)}>
          <p className="mb-4 text-texte">
            Supprimer « {aSupprimer.nom} » ? Cette action est définitive.
          </p>
          <div className="flex justify-end gap-2">
            <Bouton variante="secondaire" onClick={() => setASupprimer(null)}>
              Annuler
            </Bouton>
            <Bouton variante="danger" onClick={() => void confirmerSuppression()}>
              Supprimer
            </Bouton>
          </div>
        </Modale>
      )}

      {toast && <Toast message={toast} onFermer={() => setToast(null)} />}
    </div>
  );
}
