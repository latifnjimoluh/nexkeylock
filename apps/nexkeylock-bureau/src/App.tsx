import { useEffect, useState } from "react";
import { Bouton } from "./composants/Bouton";
import { appliquerTheme, lireTheme, type Theme } from "./lib/theme";
import { versionCoeur } from "./lib/pont";

const THEMES: { valeur: Theme; libelle: string }[] = [
  { valeur: "clair", libelle: "Clair" },
  { valeur: "sombre", libelle: "Sombre" },
  { valeur: "systeme", libelle: "Système" },
];

/** Coquille applicative (Jalon F0) : valide le pont, le design et les thèmes. */
export function App() {
  const [theme, setTheme] = useState<Theme>(lireTheme());
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    appliquerTheme(theme);
  }, [theme]);

  useEffect(() => {
    versionCoeur()
      .then(setVersion)
      .catch(() => setVersion("indisponible"));
  }, []);

  return (
    <main className="mx-auto flex min-h-full max-w-2xl flex-col items-center justify-center gap-8 p-8">
      <div className="flex flex-col items-center gap-2 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-jeton bg-accent text-2xl text-accent-contraste shadow-panneau">
          🔒
        </div>
        <h1 className="text-3xl font-semibold tracking-tight">NexKeyLock</h1>
        <p className="text-texte-doux">Gestionnaire de mots de passe à architecture zéro-connaissance</p>
      </div>

      <section className="w-full rounded-jeton border border-bordure bg-surface p-6 shadow-panneau">
        <h2 className="mb-4 text-sm font-medium uppercase tracking-wide text-texte-doux">Thème</h2>
        <div className="flex gap-2">
          {THEMES.map((t) => (
            <Bouton
              key={t.valeur}
              variante={theme === t.valeur ? "primaire" : "secondaire"}
              onClick={() => setTheme(t.valeur)}
            >
              {t.libelle}
            </Bouton>
          ))}
        </div>
        <p className="mt-6 text-sm text-texte-doux">
          Cœur cryptographique :{" "}
          <span className="font-mono text-texte">{version ?? "…"}</span>
        </p>
      </section>
    </main>
  );
}
