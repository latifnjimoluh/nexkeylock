import { useEffect, useState } from "react";
import { appliquerTheme, lireTheme, type Theme } from "../lib/theme";

const ORDRE: Theme[] = ["systeme", "clair", "sombre"];
const ICONE: Record<Theme, string> = { systeme: "🖥", clair: "☀", sombre: "🌙" };
const LIBELLE: Record<Theme, string> = { systeme: "Système", clair: "Clair", sombre: "Sombre" };

/** Bouton compact qui fait défiler les thèmes système → clair → sombre. */
export function SelecteurTheme() {
  const [theme, setTheme] = useState<Theme>(lireTheme());

  useEffect(() => {
    appliquerTheme(theme);
  }, [theme]);

  const suivant = () => {
    const i = ORDRE.indexOf(theme);
    const prochain = ORDRE[(i + 1) % ORDRE.length] ?? "systeme";
    setTheme(prochain);
  };

  return (
    <button
      type="button"
      onClick={suivant}
      aria-label={`Thème : ${LIBELLE[theme]}. Cliquer pour changer.`}
      className="flex items-center gap-2 rounded-jeton border border-bordure bg-surface px-3 py-1.5 text-sm text-texte-doux hover:text-texte"
    >
      <span aria-hidden>{ICONE[theme]}</span>
      <span>{LIBELLE[theme]}</span>
    </button>
  );
}
