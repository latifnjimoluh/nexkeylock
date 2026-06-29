import { useEffect, useRef } from "react";

/**
 * Verrouille automatiquement le coffre :
 * - après `delaiMinutes` d'inactivité (souris/clavier/défilement) ;
 * - immédiatement quand la fenêtre passe en arrière-plan (minimisation, veille,
 *   changement de bureau) via `visibilitychange`.
 *
 * Le verrouillage appelle le backend, qui efface la DEK et le contenu (zeroize).
 */
export function useVerrouillageAuto(
  delaiMinutes: number,
  onVerrouiller: () => void,
  actif: boolean,
): void {
  const rappel = useRef(onVerrouiller);
  rappel.current = onVerrouiller;

  useEffect(() => {
    if (!actif) return;
    const delaiMs = Math.max(1, delaiMinutes) * 60_000;
    let minuteur: ReturnType<typeof setTimeout>;

    const reinitialiser = () => {
      clearTimeout(minuteur);
      minuteur = setTimeout(() => rappel.current(), delaiMs);
    };
    const surVisibilite = () => {
      if (document.visibilityState === "hidden") rappel.current();
    };

    const evenements = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    evenements.forEach((e) => window.addEventListener(e, reinitialiser, { passive: true }));
    document.addEventListener("visibilitychange", surVisibilite);
    reinitialiser();

    return () => {
      clearTimeout(minuteur);
      evenements.forEach((e) => window.removeEventListener(e, reinitialiser));
      document.removeEventListener("visibilitychange", surVisibilite);
    };
  }, [delaiMinutes, actif]);
}
