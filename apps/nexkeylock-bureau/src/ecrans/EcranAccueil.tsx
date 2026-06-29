import { useState, type FormEvent } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { CadreAuth } from "../composants/CadreAuth";
import { ChampMotDePasse } from "../composants/ChampMotDePasse";
import { IndicateurForce } from "../composants/IndicateurForce";
import { Bouton } from "../composants/Bouton";
import { useBoutique } from "../lib/boutique";
import {
  estErreurCommande,
  creerCoffre,
  configurerRecuperation,
  genererFichierCle,
} from "../lib/pont";

const LONGUEUR_MIN = 8;

/** Écran de création du coffre + code de récupération optionnel. */
export function EcranAccueil() {
  const charger = useBoutique((b) => b.charger);

  const [motDePasse, setMotDePasse] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [recuperationVoulue, setRecuperationVoulue] = useState(true);
  const [fichierCleVoulu, setFichierCleVoulu] = useState(false);
  const [erreur, setErreur] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);

  // Phase d'affichage unique du code de récupération.
  const [code, setCode] = useState<string | null>(null);
  const [sauvegarde, setSauvegarde] = useState(false);

  const tropCourt = motDePasse.length > 0 && motDePasse.length < LONGUEUR_MIN;
  const discordance = confirmation.length > 0 && confirmation !== motDePasse;
  const valide = motDePasse.length >= LONGUEUR_MIN && confirmation === motDePasse;

  const soumettre = async (e: FormEvent) => {
    e.preventDefault();
    if (occupe || !valide) return;
    setErreur(null);
    setOccupe(true);
    try {
      let cheminFichierCle: string | undefined;
      if (fichierCleVoulu) {
        const ch = await save({
          defaultPath: "nexkeylock.cle",
          filters: [{ name: "Fichier-clé", extensions: ["cle"] }],
        });
        if (!ch) {
          setErreur("Création annulée : aucun emplacement choisi pour le fichier-clé.");
          return;
        }
        await genererFichierCle(ch);
        cheminFichierCle = ch;
      }
      await creerCoffre(motDePasse, cheminFichierCle);
      setMotDePasse("");
      setConfirmation("");
      if (recuperationVoulue) {
        setCode(await configurerRecuperation());
      } else {
        await charger(); // route vers le coffre déverrouillé
      }
    } catch (e) {
      setErreur(estErreurCommande(e) ? e.message : "Création impossible.");
    } finally {
      setOccupe(false);
    }
  };

  const terminer = async () => {
    setCode(null); // efface le code de la mémoire
    await charger();
  };

  if (code !== null) {
    return (
      <CadreAuth
        titre="Code de récupération"
        sousTitre="Notez-le hors ligne : il ne sera plus jamais affiché."
      >
        <div className="flex flex-col gap-4">
          <code className="select-all break-all rounded-jeton border border-bordure bg-surface-haute px-4 py-3 text-center font-mono text-accent">
            {code}
          </code>
          <p className="rounded-jeton bg-alerte/10 px-3 py-2 text-sm text-alerte">
            Sans ce code NI votre mot de passe maître, le coffre est définitivement irrécupérable.
          </p>
          <label className="flex items-center gap-2 text-sm text-texte">
            <input
              type="checkbox"
              checked={sauvegarde}
              onChange={(e) => setSauvegarde(e.target.checked)}
            />
            J'ai sauvegardé ce code en lieu sûr.
          </label>
          <Bouton onClick={terminer} disabled={!sauvegarde}>
            Continuer
          </Bouton>
        </div>
      </CadreAuth>
    );
  }

  return (
    <CadreAuth titre="Créer votre coffre" sousTitre="Choisissez un mot de passe maître fort.">
      <form onSubmit={soumettre} className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <ChampMotDePasse
            etiquette="Mot de passe maître"
            valeur={motDePasse}
            onValeur={setMotDePasse}
            autoFocus
          />
          <IndicateurForce motDePasse={motDePasse} />
          {tropCourt && <p className="text-xs text-danger">Au moins {LONGUEUR_MIN} caractères.</p>}
        </div>

        <ChampMotDePasse
          etiquette="Confirmer le mot de passe"
          valeur={confirmation}
          onValeur={setConfirmation}
        />
        {discordance && (
          <p className="text-xs text-danger">Les mots de passe ne correspondent pas.</p>
        )}

        <label className="flex items-center gap-2 text-sm text-texte">
          <input
            type="checkbox"
            checked={recuperationVoulue}
            onChange={(e) => setRecuperationVoulue(e.target.checked)}
          />
          Générer un code de récupération
        </label>

        <label className="flex items-start gap-2 text-sm text-texte">
          <input
            type="checkbox"
            checked={fichierCleVoulu}
            onChange={(e) => setFichierCleVoulu(e.target.checked)}
            className="mt-1"
          />
          <span>
            Protéger aussi avec un <strong>fichier-clé</strong> (second facteur). À conserver
            séparément du coffre et sur chaque appareil ; sans lui, le coffre est inutilisable.
          </span>
        </label>

        <p className="rounded-jeton bg-alerte/10 px-3 py-2 text-sm text-alerte">
          Votre mot de passe maître est <strong>impossible à récupérer</strong>. Conservez-le
          précieusement.
        </p>

        {erreur && (
          <p role="alert" className="rounded-jeton bg-danger/10 px-3 py-2 text-sm text-danger">
            {erreur}
          </p>
        )}

        <Bouton type="submit" disabled={occupe || !valide}>
          {occupe ? "Création…" : "Créer le coffre"}
        </Bouton>
      </form>
    </CadreAuth>
  );
}
