import { useId, useState, type InputHTMLAttributes } from "react";

interface Proprietes extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  etiquette: string;
  valeur: string;
  onValeur: (v: string) => void;
}

/** Champ de saisie de mot de passe avec bascule afficher/masquer (accessible). */
export function ChampMotDePasse({
  etiquette,
  valeur,
  onValeur,
  id,
  autoFocus,
  ...reste
}: Proprietes) {
  const idAuto = useId();
  const idChamp = id ?? idAuto;
  const [visible, setVisible] = useState(false);

  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={idChamp} className="text-sm font-medium text-texte">
        {etiquette}
      </label>
      <div className="relative">
        <input
          id={idChamp}
          type={visible ? "text" : "password"}
          value={valeur}
          onChange={(e) => onValeur(e.target.value)}
          autoFocus={autoFocus}
          autoComplete="off"
          spellCheck={false}
          className="w-full rounded-jeton border border-bordure bg-surface px-3 py-2 pr-11 font-mono text-texte placeholder:text-texte-doux"
          {...reste}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? "Masquer le mot de passe" : "Afficher le mot de passe"}
          aria-pressed={visible}
          className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-texte-doux hover:text-texte"
        >
          {visible ? "🙈" : "👁"}
        </button>
      </div>
    </div>
  );
}
