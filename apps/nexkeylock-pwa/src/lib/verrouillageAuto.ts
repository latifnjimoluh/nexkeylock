import { useEffect, useRef } from "react";

/**
 * Verrouille automatiquement après `delaiMinutes` d'inactivité, et immédiatement
 * quand l'onglet passe en arrière-plan (`visibilitychange`). Le verrouillage
 * efface le coffre dans le Web Worker (les secrets quittent la mémoire).
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
