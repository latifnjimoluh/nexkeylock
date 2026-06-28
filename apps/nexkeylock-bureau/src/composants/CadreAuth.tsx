import type { ReactNode } from "react";
import { SelecteurTheme } from "./SelecteurTheme";

interface Proprietes {
  titre: string;
  sousTitre?: string;
  // `children` est le nom imposé par React pour le contenu imbriqué en JSX.
  children: ReactNode;
}

/** Cadre centré commun aux écrans d'authentification (création, verrouillage). */
export function CadreAuth({ titre, sousTitre, children }: Proprietes) {
  return (
    <div className="flex min-h-full flex-col">
      <header className="flex justify-end p-4">
        <SelecteurTheme />
      </header>
      <main className="flex flex-1 items-center justify-center p-6">
        <section className="w-full max-w-md rounded-jeton border border-bordure bg-surface p-8 shadow-panneau">
          <div className="mb-6 flex flex-col items-center gap-3 text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-jeton bg-accent text-2xl text-accent-contraste">
              🔒
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">{titre}</h1>
              {sousTitre && <p className="mt-1 text-sm text-texte-doux">{sousTitre}</p>}
            </div>
          </div>
          {children}
        </section>
      </main>
    </div>
  );
}
