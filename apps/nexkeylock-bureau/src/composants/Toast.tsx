import { useEffect } from "react";

interface Proprietes {
  message: string;
  onFermer: () => void;
  dureeMs?: number;
}

/** Notification éphémère (confirmation de copie, etc.). */
export function Toast({ message, onFermer, dureeMs = 3000 }: Proprietes) {
  useEffect(() => {
    const t = setTimeout(onFermer, dureeMs);
    return () => clearTimeout(t);
  }, [message, dureeMs, onFermer]);

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-6 left-1/2 -translate-x-1/2 rounded-jeton border border-bordure bg-surface-haute px-4 py-2 text-sm text-texte shadow-panneau"
    >
      {message}
    </div>
  );
}
