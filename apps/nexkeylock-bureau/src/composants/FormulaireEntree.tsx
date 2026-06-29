import { useState, type FormEvent } from "react";
import { Modale } from "./Modale";
import { Bouton } from "./Bouton";
import { ChampMotDePasse } from "./ChampMotDePasse";
import { GenerateurMotDePasse } from "./GenerateurMotDePasse";
import {
  ajouterEntree,
  modifierEntree,
  estErreurCommande,
  type DonneesEntree,
  type EntreeApercu,
} from "../lib/pont";

interface Proprietes {
  /** Entrée à modifier (métadonnées) ; absent => création. */
  initiale?: EntreeApercu | null;
  onFerme: () => void;
  onEnregistre: () => void;
}

const CATEGORIES = [
  { valeur: "connexion", libelle: "Connexion" },
  { valeur: "note", libelle: "Note sécurisée" },
  { valeur: "secret", libelle: "Secret générique" },
];

/** Formulaire de création/modification d'une entrée. */
export function FormulaireEntree({ initiale, onFerme, onEnregistre }: Proprietes) {
  const edition = initiale != null;

  const [categorie, setCategorie] = useState(initiale?.categorie ?? "connexion");
  const [nom, setNom] = useState(initiale?.nom ?? "");
  const [nomUtilisateur, setNomUtilisateur] = useState(initiale?.nomUtilisateur ?? "");
  const [uris, setUris] = useState((initiale?.uris ?? []).join("\n"));
  const [motDePasse, setMotDePasse] = useState("");
  const [totp, setTotp] = useState("");
  const [notes, setNotes] = useState("");
  const [generateurVisible, setGenerateurVisible] = useState(false);
  const [erreur, setErreur] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);

  const soumettre = async (e: FormEvent) => {
    e.preventDefault();
    if (occupe || nom.trim().length === 0) return;
    setErreur(null);
    setOccupe(true);
    const donnees: DonneesEntree = {
      categorie,
      nom: nom.trim(),
      nomUtilisateur: nomUtilisateur.trim() || null,
      uris: uris
        .split(/[\s,]+/)
        .map((u) => u.trim())
        .filter((u) => u.length > 0),
      motDePasse: motDePasse || null,
      totp: totp || null,
      notes: notes || null,
    };
    try {
      if (edition && initiale) {
        await modifierEntree(initiale.id, donnees);
      } else {
        await ajouterEntree(donnees);
      }
      onEnregistre();
      onFerme();
    } catch (e) {
      setErreur(estErreurCommande(e) ? e.message : "Enregistrement impossible.");
    } finally {
      setOccupe(false);
    }
  };

  return (
    <Modale titre={edition ? "Modifier l'entrée" : "Nouvelle entrée"} onFermer={onFerme}>
      <form onSubmit={soumettre} className="flex flex-col gap-4">
        <Champ etiquette="Catégorie">
          <select
            value={categorie}
            onChange={(e) => setCategorie(e.target.value)}
            className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 text-texte"
          >
            {CATEGORIES.map((c) => (
              <option key={c.valeur} value={c.valeur}>
                {c.libelle}
              </option>
            ))}
          </select>
        </Champ>

        <Champ etiquette="Nom">
          <input
            value={nom}
            onChange={(e) => setNom(e.target.value)}
            required
            autoFocus
            className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 text-texte"
          />
        </Champ>

        <Champ etiquette="Identifiant / utilisateur">
          <input
            value={nomUtilisateur}
            onChange={(e) => setNomUtilisateur(e.target.value)}
            className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 text-texte"
          />
        </Champ>

        <Champ etiquette="Adresses (une par ligne)">
          <textarea
            value={uris}
            onChange={(e) => setUris(e.target.value)}
            rows={2}
            placeholder="https://exemple.fr"
            className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 font-mono text-texte"
          />
        </Champ>

        <div className="flex flex-col gap-2">
          <ChampMotDePasse
            etiquette={edition ? "Mot de passe (laisser vide = inchangé)" : "Mot de passe"}
            valeur={motDePasse}
            onValeur={setMotDePasse}
          />
          <button
            type="button"
            onClick={() => setGenerateurVisible((v) => !v)}
            className="self-start text-sm text-accent hover:underline"
          >
            {generateurVisible ? "Masquer le générateur" : "Générer un mot de passe"}
          </button>
          {generateurVisible && (
            <GenerateurMotDePasse
              onUtiliser={(v) => {
                setMotDePasse(v);
                setGenerateurVisible(false);
              }}
            />
          )}
        </div>

        <Champ
          etiquette={
            edition ? "Secret TOTP (laisser vide = inchangé)" : "Secret TOTP (Base32 ou otpauth://)"
          }
        >
          <input
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
            placeholder="JBSWY3DPEHPK3PXP ou otpauth://totp/…"
            className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 font-mono text-texte"
          />
        </Champ>

        <Champ etiquette="Notes">
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 text-texte"
          />
        </Champ>

        {erreur && (
          <p role="alert" className="rounded-jeton bg-danger/10 px-3 py-2 text-sm text-danger">
            {erreur}
          </p>
        )}

        <div className="flex justify-end gap-2">
          <Bouton variante="secondaire" onClick={onFerme}>
            Annuler
          </Bouton>
          <Bouton type="submit" disabled={occupe || nom.trim().length === 0}>
            {occupe ? "Enregistrement…" : "Enregistrer"}
          </Bouton>
        </div>
      </form>
    </Modale>
  );
}

function Champ({ etiquette, children }: { etiquette: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-sm font-medium text-texte">{etiquette}</span>
      {children}
    </label>
  );
}
