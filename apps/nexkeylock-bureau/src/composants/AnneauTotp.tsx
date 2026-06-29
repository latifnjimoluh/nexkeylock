import { useCallback, useEffect, useState } from "react";
import { obtenirTotp } from "../lib/pont";

interface Proprietes {
  id: string;
}

const PAS = 30;
const RAYON = 14;
const CIRCONFERENCE = 2 * Math.PI * RAYON;

/** Affiche le code TOTP courant avec un anneau de décompte en direct. */
export function AnneauTotp({ id }: Proprietes) {
  const [code, setCode] = useState<string | null>(null);
  const [restant, setRestant] = useState(PAS);
  const [erreur, setErreur] = useState(false);

  const charger = useCallback(async () => {
    try {
      const t = await obtenirTotp(id);
      setCode(t.code);
      setRestant(t.secondesRestantes);
      setErreur(false);
    } catch {
      setErreur(true);
    }
  }, [id]);

  useEffect(() => {
    void charger();
  }, [charger]);

  useEffect(() => {
    const minuteur = setInterval(() => {
      setRestant((r) => {
        if (r <= 1) {
          void charger();
          return PAS;
        }
        return r - 1;
      });
    }, 1000);
    return () => clearInterval(minuteur);
  }, [charger]);

  if (erreur) {
    return <span className="text-sm text-danger">TOTP indisponible</span>;
  }

  const offset = CIRCONFERENCE * (1 - restant / PAS);

  return (
    <div className="flex items-center gap-3">
      <span className="font-mono text-2xl tracking-widest text-accent">{code ?? "······"}</span>
      <svg width="36" height="36" viewBox="0 0 36 36" aria-label={`Expire dans ${restant} secondes`}>
        <circle cx="18" cy="18" r={RAYON} fill="none" stroke="rgb(var(--c-surface-haute))" strokeWidth="3" />
        <circle
          cx="18"
          cy="18"
          r={RAYON}
          fill="none"
          stroke="rgb(var(--c-accent))"
          strokeWidth="3"
          strokeDasharray={CIRCONFERENCE}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 18 18)"
          style={{ transition: "stroke-dashoffset 1s linear" }}
        />
        <text x="18" y="22" textAnchor="middle" className="fill-texte-doux text-[10px]">
          {restant}
        </text>
      </svg>
    </div>
  );
}
