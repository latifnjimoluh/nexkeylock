import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { IndicateurForce } from "./IndicateurForce";

describe("IndicateurForce", () => {
  it("affiche 0 bit pour un mot de passe vide", () => {
    render(<IndicateurForce motDePasse="" />);
    const barre = screen.getByRole("progressbar", { name: "Force du mot de passe" });
    expect(barre).toHaveAttribute("aria-valuenow", "0");
  });

  it("qualifie un mot de passe fort d'excellent", () => {
    render(<IndicateurForce motDePasse="Corr3ct-Cheval-Batterie-Agrafe!2026" />);
    expect(screen.getByText("Excellent")).toBeInTheDocument();
  });

  it("qualifie un mot de passe court de faible", () => {
    render(<IndicateurForce motDePasse="abc" />);
    expect(screen.getByText("Faible")).toBeInTheDocument();
  });
});
