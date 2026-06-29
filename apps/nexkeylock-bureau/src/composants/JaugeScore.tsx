interface Proprietes {
  score: number;
}

const RAYON = 52;
const CIRCONFERENCE = 2 * Math.PI * RAYON;

/** Jauge circulaire du score de santé (0–100), colorée selon le niveau. */
export function JaugeScore({ score }: Proprietes) {
  const borne = Math.max(0, Math.min(100, score));
  const offset = CIRCONFERENCE * (1 - borne / 100);
  const couleur =
    borne >= 80
      ? "rgb(var(--c-succes))"
      : borne >= 50
        ? "rgb(var(--c-alerte))"
        : "rgb(var(--c-danger))";

  return (
    <svg
      width="140"
      height="140"
      viewBox="0 0 120 120"
      role="img"
      aria-label={`Score de santé : ${borne} sur 100`}
    >
      <circle
        cx="60"
        cy="60"
        r={RAYON}
        fill="none"
        stroke="rgb(var(--c-surface-haute))"
        strokeWidth="10"
      />
      <circle
        cx="60"
        cy="60"
        r={RAYON}
        fill="none"
        stroke={couleur}
        strokeWidth="10"
        strokeDasharray={CIRCONFERENCE}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 60 60)"
        style={{ transition: "stroke-dashoffset 0.6s ease" }}
      />
      <text x="60" y="60" textAnchor="middle" className="fill-texte text-2xl font-semibold">
        {borne}
      </text>
      <text x="60" y="80" textAnchor="middle" className="fill-texte-doux text-[11px]">
        / 100
      </text>
    </svg>
  );
}
