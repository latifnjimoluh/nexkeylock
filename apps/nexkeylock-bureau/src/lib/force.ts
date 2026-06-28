/**
 * Estimation **indicative** de la force d'un mot de passe maître (UX seulement).
 *
 * Ce n'est PAS de la cryptographie : c'est un repère visuel pour l'utilisateur,
 * calculé localement à partir de la taille du jeu de caractères employé. La
 * vraie dérivation (Argon2id) reste côté cœur Rust.
 */

export type NiveauForce = "vide" | "faible" | "moyen" | "bon" | "excellent";

export interface Force {
  bits: number;
  niveau: NiveauForce;
}

/** Estime l'entropie (bits) et le niveau d'un mot de passe. */
export function estimerForce(motDePasse: string): Force {
  if (motDePasse.length === 0) {
    return { bits: 0, niveau: "vide" };
  }

  let taillePool = 0;
  if (/[a-z]/.test(motDePasse)) taillePool += 26;
  if (/[A-Z]/.test(motDePasse)) taillePool += 26;
  if (/[0-9]/.test(motDePasse)) taillePool += 10;
  if (/[^a-zA-Z0-9]/.test(motDePasse)) taillePool += 33;

  const bits = Math.round(motDePasse.length * Math.log2(Math.max(taillePool, 1)));

  let niveau: NiveauForce;
  if (bits < 40) niveau = "faible";
  else if (bits < 70) niveau = "moyen";
  else if (bits < 100) niveau = "bon";
  else niveau = "excellent";

  return { bits, niveau };
}

/** Libellé lisible d'un niveau. */
export function libelleNiveau(niveau: NiveauForce): string {
  switch (niveau) {
    case "vide":
      return "—";
    case "faible":
      return "Faible";
    case "moyen":
      return "Moyen";
    case "bon":
      return "Bon";
    case "excellent":
      return "Excellent";
  }
}
