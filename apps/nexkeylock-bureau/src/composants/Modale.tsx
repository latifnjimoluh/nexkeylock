import { useEffect, type ReactNode } from "react";

interface Proprietes {
  titre: string;
  onFermer: () => void;
  children: ReactNode;
}

/** Boîte de dialogue modale accessible (fermeture par Échap ou clic arrière-plan). */
export function Modale({ titre, onFermer, children }: Proprietes) {
  useEffect(() => {
    const surTouche = (e: KeyboardEvent) => {
      if (e.key === "Escape") onFermer();
    };
    document.addEventListener("keydown", surTouche);
    return () => document.removeEventListener("keydown", surTouche);
  }, [onFermer]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onFermer}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={titre}
        className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-jeton border border-bordure bg-surface p-6 shadow-panneau"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-texte">{titre}</h2>
          <button
            type="button"
            onClick={onFermer}
            aria-label="Fermer"
            className="text-texte-doux hover:text-texte"
          >
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
