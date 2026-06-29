import { useEffect, useState, type FormEvent } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { CadreAuth } from "../composants/CadreAuth";
import { ChampMotDePasse } from "../composants/ChampMotDePasse";
import { Bouton } from "../composants/Bouton";
import { useBoutique } from "../lib/boutique";
import { estErreurCommande, fichierCleRequise } from "../lib/pont";

/** Écran de déverrouillage : mot de passe maître (+ fichier-clé si requis). */
export function EcranVerrouillage() {
  const deverrouiller = useBoutique((b) => b.deverrouiller);
  const [motDePasse, setMotDePasse] = useState("");
  const [erreur, setErreur] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);
  const [requisFichierCle, setRequisFichierCle] = useState(false);
  const [cheminFichierCle, setCheminFichierCle] = useState<string | null>(null);

  useEffect(() => {
    fichierCleRequise()
      .then(setRequisFichierCle)
      .catch(() => undefined);
  }, []);

  const choisirFichierCle = async () => {
    try {
      const sel = await open({ multiple: false });
      if (typeof sel === "string") setCheminFichierCle(sel);
    } catch {
      setErreur("Sélection du fichier-clé impossible.");
    }
  };

  const pretAEnvoyer = motDePasse.length > 0 && (!requisFichierCle || cheminFichierCle !== null);

  const soumettre = async (e: FormEvent) => {
    e.preventDefault();
    if (occupe || !pretAEnvoyer) return;
    setErreur(null);
    setOccupe(true);
    try {
      await deverrouiller(motDePasse, cheminFichierCle ?? undefined);
      setMotDePasse(""); // efface le secret de l'état dès que possible
    } catch (e) {
      setErreur(estErreurCommande(e) ? e.message : "Échec du déverrouillage.");
      setMotDePasse("");
    } finally {
      setOccupe(false);
    }
  };

  return (
    <CadreAuth
      titre="NexKeyLock"
      sousTitre="Saisissez votre mot de passe maître pour déverrouiller."
    >
      <form onSubmit={soumettre} className="flex flex-col gap-4">
        <ChampMotDePasse
          etiquette="Mot de passe maître"
          valeur={motDePasse}
          onValeur={setMotDePasse}
          autoFocus
        />

        {requisFichierCle && (
          <div className="flex flex-col gap-1.5">
            <span className="text-sm font-medium text-texte">
              Fichier-clé (second facteur requis)
            </span>
            <div className="flex items-center gap-2">
              <Bouton variante="secondaire" onClick={() => void choisirFichierCle()}>
                Choisir le fichier-clé…
              </Bouton>
              {cheminFichierCle && (
                <span className="truncate text-xs text-succes" title={cheminFichierCle}>
                  ✓ sélectionné
                </span>
              )}
            </div>
          </div>
        )}

        {erreur && (
          <p role="alert" className="rounded-jeton bg-danger/10 px-3 py-2 text-sm text-danger">
            {erreur}
          </p>
        )}
        <Bouton type="submit" disabled={occupe || !pretAEnvoyer}>
          {occupe ? "Déverrouillage…" : "Déverrouiller"}
        </Bouton>
      </form>
    </CadreAuth>
  );
}
