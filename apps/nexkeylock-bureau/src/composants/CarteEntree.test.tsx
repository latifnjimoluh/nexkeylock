import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { CarteEntree } from "./CarteEntree";
import type { EntreeApercu } from "../lib/pont";

const chargeXss = '<script>window.__xss = true;</script><img src=x onerror="alert(1)">';

const entree: EntreeApercu = {
  id: "1",
  nom: chargeXss,
  nomUtilisateur: chargeXss,
  uris: [],
  categorie: "connexion",
  aMotDePasse: true,
  aTotp: false,
};

describe("CarteEntree — anti-XSS", () => {
  it("rend le nom et l'utilisateur comme texte inerte", () => {
    const { container } = render(
      <CarteEntree entree={entree} selectionnee={false} onClick={vi.fn()} />,
    );
    // Le contenu est affiché littéralement (échappé par React).
    expect(screen.getAllByText(chargeXss).length).toBeGreaterThan(0);
    // Aucune balise <script> ni <img> n'a été injectée dans le DOM.
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    // Aucun effet de bord du script.
    expect((window as unknown as { __xss?: boolean }).__xss).toBeUndefined();
  });
});
