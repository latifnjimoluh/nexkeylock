import { useEffect, useState } from "react";
import type { EntreeApercu } from "../lib/pont";
import { revelerChamp, copierChamp, copierTotp } from "../lib/pont";
import { Bouton } from "./Bouton";
import { AnneauTotp } from "./AnneauTotp";

/** Délai d'effacement du presse-papiers (s). Configurable au Jalon F7. */
const DELAI_COPIE = 20;

interface Proprietes {
  entree: EntreeApercu;
  onToast: (message: string) => void;
  onModifier: () => void;
  onSupprimer: () => void;
}

/** Panneau de détail d'une entrée : champs, révélation, copie, TOTP. */
export function PanneauDetail({ entree, onToast, onModifier, onSupprimer }: Proprietes) {
  const [motDePasse, setMotDePasse] = useState<string | null>(null);

  // Masque le mot de passe dès qu'on change d'entrée (n'expose rien par défaut).
  useEffect(() => {
    setMotDePasse(null);
  }, [entree.id]);

  const afficher = async () => {
    if (motDePasse !== null) {
      setMotDePasse(null);
      return;
    }
    try {
      setMotDePasse(await revelerChamp(entree.id, "mot_de_passe"));
    } catch {
      onToast("Révélation impossible.");
    }
  };

  const copierMdp = async () => {
    try {
      await copierChamp(entree.id, "mot_de_passe", DELAI_COPIE);
      onToast(`Mot de passe copié — effacement dans ${DELAI_COPIE} s.`);
    } catch {
      onToast("Copie impossible.");
    }
  };

  const copierCodeTotp = async () => {
    try {
      await copierTotp(entree.id, DELAI_COPIE);
      onToast(`Code TOTP copié — effacement dans ${DELAI_COPIE} s.`);
    } catch {
      onToast("Copie impossible.");
    }
  };

  return (
    <div className="flex h-full flex-col gap-6 overflow-y-auto p-6">
      <header className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-xl font-semibold text-texte">{entree.nom}</h2>
          <p className="text-sm capitalize text-texte-doux">{entree.categorie}</p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Bouton variante="secondaire" onClick={onModifier}>
            Modifier
          </Bouton>
          <Bouton variante="danger" onClick={onSupprimer}>
            Supprimer
          </Bouton>
        </div>
      </header>

      {entree.nomUtilisateur && (
        <Champ etiquette="Identifiant">
          <span className="select-all font-mono text-texte">{entree.nomUtilisateur}</span>
        </Champ>
      )}

      {entree.aMotDePasse && (
        <Champ etiquette="Mot de passe">
          <div className="flex items-center gap-2">
            <span className="flex-1 select-all break-all font-mono text-texte">
              {motDePasse ?? "••••••••••••"}
            </span>
            <Bouton variante="secondaire" onClick={afficher}>
              {motDePasse !== null ? "Masquer" : "Afficher"}
            </Bouton>
            <Bouton variante="secondaire" onClick={copierMdp}>
              Copier
            </Bouton>
          </div>
        </Champ>
      )}

      {entree.aTotp && (
        <Champ etiquette="Code à usage unique (TOTP)">
          <div className="flex items-center justify-between gap-2">
            <AnneauTotp id={entree.id} />
            <Bouton variante="secondaire" onClick={copierCodeTotp}>
              Copier
            </Bouton>
          </div>
        </Champ>
      )}

      {entree.uris.length > 0 && (
        <Champ etiquette="Adresses">
          <ul className="flex flex-col gap-1">
            {entree.uris.map((u) => (
              <li key={u} className="select-all break-all text-sm text-texte-doux">
                {u}
              </li>
            ))}
          </ul>
        </Champ>
      )}
    </div>
  );
}

function Champ({ etiquette, children }: { etiquette: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs font-medium uppercase tracking-wide text-texte-doux">
        {etiquette}
      </span>
      {children}
    </div>
  );
}
