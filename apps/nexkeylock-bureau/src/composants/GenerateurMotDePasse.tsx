import { useCallback, useEffect, useState } from "react";
import { genererMotDePasse, type MotDePasseGenere, type OptionsGenerateur } from "../lib/pont";
import { Bouton } from "./Bouton";

interface Proprietes {
  /** Si fourni, affiche un bouton « Utiliser » qui renvoie la valeur générée. */
  onUtiliser?: (valeur: string) => void;
}

type Mode = "motdepasse" | "phrase";

/** Générateur paramétrable (mot de passe ou phrase de passe), entropie en direct. */
export function GenerateurMotDePasse({ onUtiliser }: Proprietes) {
  const [mode, setMode] = useState<Mode>("motdepasse");
  const [longueur, setLongueur] = useState(20);
  const [nbMots, setNbMots] = useState(5);
  const [minuscules, setMinuscules] = useState(true);
  const [majuscules, setMajuscules] = useState(true);
  const [chiffres, setChiffres] = useState(true);
  const [symboles, setSymboles] = useState(true);
  const [exclureAmbigus, setExclureAmbigus] = useState(true);
  const [resultat, setResultat] = useState<MotDePasseGenere | null>(null);
  const [erreur, setErreur] = useState<string | null>(null);

  const options = useCallback((): OptionsGenerateur => {
    if (mode === "phrase") {
      return {
        mots: nbMots,
        longueur,
        minuscules,
        majuscules,
        chiffres,
        symboles,
        exclureAmbigus,
      };
    }
    return { mots: null, longueur, minuscules, majuscules, chiffres, symboles, exclureAmbigus };
  }, [mode, nbMots, longueur, minuscules, majuscules, chiffres, symboles, exclureAmbigus]);

  const generer = useCallback(async () => {
    try {
      setResultat(await genererMotDePasse(options()));
      setErreur(null);
    } catch {
      setErreur("Combinaison d'options invalide (activez au moins un type de caractère).");
    }
  }, [options]);

  useEffect(() => {
    void generer();
  }, [generer]);

  return (
    <div className="flex flex-col gap-4 rounded-jeton border border-bordure bg-surface-haute p-4">
      <div className="flex gap-2">
        <Bouton variante={mode === "motdepasse" ? "primaire" : "secondaire"} onClick={() => setMode("motdepasse")}>
          Mot de passe
        </Bouton>
        <Bouton variante={mode === "phrase" ? "primaire" : "secondaire"} onClick={() => setMode("phrase")}>
          Phrase de passe
        </Bouton>
      </div>

      {mode === "motdepasse" ? (
        <>
          <label className="flex items-center justify-between gap-3 text-sm">
            <span>Longueur : {longueur}</span>
            <input
              type="range"
              min={8}
              max={64}
              value={longueur}
              onChange={(e) => setLongueur(Number(e.target.value))}
              aria-label="Longueur"
              className="flex-1"
            />
          </label>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <Case libelle="Minuscules" coche={minuscules} onChange={setMinuscules} />
            <Case libelle="Majuscules" coche={majuscules} onChange={setMajuscules} />
            <Case libelle="Chiffres" coche={chiffres} onChange={setChiffres} />
            <Case libelle="Symboles" coche={symboles} onChange={setSymboles} />
            <Case libelle="Exclure les ambigus" coche={exclureAmbigus} onChange={setExclureAmbigus} />
          </div>
        </>
      ) : (
        <label className="flex items-center justify-between gap-3 text-sm">
          <span>Nombre de mots : {nbMots}</span>
          <input
            type="range"
            min={3}
            max={10}
            value={nbMots}
            onChange={(e) => setNbMots(Number(e.target.value))}
            aria-label="Nombre de mots"
            className="flex-1"
          />
        </label>
      )}

      <div className="rounded-jeton border border-bordure bg-surface px-3 py-2">
        <p className="break-all font-mono text-accent" aria-live="polite">
          {erreur ? <span className="text-danger">{erreur}</span> : (resultat?.valeur ?? "…")}
        </p>
        {resultat && !erreur && (
          <p className="mt-1 text-xs text-texte-doux">~{resultat.entropieBits} bits d'entropie</p>
        )}
      </div>

      <div className="flex gap-2">
        <Bouton variante="secondaire" onClick={() => void generer()}>
          Régénérer
        </Bouton>
        {onUtiliser && resultat && !erreur && (
          <Bouton onClick={() => onUtiliser(resultat.valeur)}>Utiliser</Bouton>
        )}
      </div>
    </div>
  );
}

function Case({
  libelle,
  coche,
  onChange,
}: {
  libelle: string;
  coche: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={coche} onChange={(e) => onChange(e.target.checked)} />
      {libelle}
    </label>
  );
}
