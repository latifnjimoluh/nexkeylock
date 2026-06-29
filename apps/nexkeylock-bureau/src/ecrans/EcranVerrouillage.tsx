import { useState, type FormEvent } from "react";
import { CadreAuth } from "../composants/CadreAuth";
import { ChampMotDePasse } from "../composants/ChampMotDePasse";
import { Bouton } from "../composants/Bouton";
import { useBoutique } from "../lib/boutique";
import { estErreurCommande } from "../lib/pont";

/** Écran de déverrouillage : saisie du mot de passe maître. */
export function EcranVerrouillage() {
  const deverrouiller = useBoutique((b) => b.deverrouiller);
  const [motDePasse, setMotDePasse] = useState("");
  const [erreur, setErreur] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);

  const soumettre = async (e: FormEvent) => {
    e.preventDefault();
    if (occupe || motDePasse.length === 0) return;
    setErreur(null);
    setOccupe(true);
    try {
      await deverrouiller(motDePasse);
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
        {erreur && (
          <p role="alert" className="rounded-jeton bg-danger/10 px-3 py-2 text-sm text-danger">
            {erreur}
          </p>
        )}
        <Bouton type="submit" disabled={occupe || motDePasse.length === 0}>
          {occupe ? "Déverrouillage…" : "Déverrouiller"}
        </Bouton>
      </form>
    </CadreAuth>
  );
}
