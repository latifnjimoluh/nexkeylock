/**
 * Gestion du thème (clair / sombre / système).
 *
 * Le choix est une *préférence*, pas un secret : il peut être persisté dans
 * `localStorage` sans enfreindre la règle « aucun secret en stockage navigateur ».
 */

export type Theme = "clair" | "sombre" | "systeme";

const CLE = "nexkeylock.theme";

/** Lit la préférence enregistrée (défaut : « systeme »). */
export function lireTheme(): Theme {
  const valeur = localStorage.getItem(CLE);
  if (valeur === "clair" || valeur === "sombre" || valeur === "systeme") {
    return valeur;
  }
  return "systeme";
}

/** Résout « systeme » vers le thème effectif selon les préférences de l'OS. */
function resoudre(theme: Theme): "clair" | "sombre" {
  if (theme === "systeme") {
    const sombre = window.matchMedia("(prefers-color-scheme: dark)").matches;
    return sombre ? "sombre" : "clair";
  }
  return theme;
}

/** Applique le thème au document et l'enregistre. */
export function appliquerTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", resoudre(theme));
  localStorage.setItem(CLE, theme);
}

/** Initialise le thème au démarrage et suit les changements système. */
export function initialiserTheme(): void {
  const theme = lireTheme();
  appliquerTheme(theme);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (lireTheme() === "systeme") {
      appliquerTheme("systeme");
    }
  });
}
