import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variante = "primaire" | "secondaire" | "danger" | "fantome";

interface ProprietesBouton extends ButtonHTMLAttributes<HTMLButtonElement> {
  variante?: Variante;
  enfants?: ReactNode;
}

const STYLES: Record<Variante, string> = {
  primaire: "bg-accent text-accent-contraste hover:opacity-90",
  secondaire: "bg-surface-haute text-texte border border-bordure hover:bg-surface",
  danger: "bg-danger text-white hover:opacity-90",
  fantome: "bg-transparent text-texte-doux hover:text-texte hover:bg-surface-haute",
};

/** Bouton du système de design : variantes sémantiques, focus accessible. */
export function Bouton({
  variante = "primaire",
  enfants,
  children,
  className = "",
  type = "button",
  ...reste
}: ProprietesBouton) {
  return (
    <button
      type={type}
      className={`inline-flex items-center justify-center gap-2 rounded-jeton px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${STYLES[variante]} ${className}`}
      {...reste}
    >
      {enfants ?? children}
    </button>
  );
}
