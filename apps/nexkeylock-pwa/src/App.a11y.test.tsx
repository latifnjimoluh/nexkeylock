import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import axe from "axe-core";

// Cœur (Web Worker WASM) indisponible sous jsdom : on le simule.
vi.mock("./lib/coeur", () => ({
  coeur: {
    creer: vi.fn(),
    ouvrir: vi.fn(),
    lister: vi.fn(),
    reveler: vi.fn(),
    ajouter: vi.fn(),
    octets: vi.fn(),
    verrouiller: vi.fn(),
    hashAuth: vi.fn(),
    generer: vi.fn(),
    fichierCleRequis: vi.fn(),
  },
}));
vi.mock("./lib/stockage", () => ({
  coffreExiste: vi.fn().mockResolvedValue(false),
  lireCoffre: vi.fn(),
  ecrireCoffre: vi.fn(),
}));

import { App } from "./App";

describe("Accessibilité (axe)", () => {
  it("l'écran de création n'a aucune violation sérieuse/critique", async () => {
    const { container } = render(<App />);
    // Attend le rendu réel (sortie de l'état « Chargement… »).
    await screen.findByRole("button", { name: "Créer le coffre" });

    const resultats = await axe.run(container, {
      // jsdom ne calcule pas les couleurs : on cible structure/labels/rôles.
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa"] },
      rules: { "color-contrast": { enabled: false } },
    });

    const graves = resultats.violations.filter(
      (v) => v.impact === "serious" || v.impact === "critical",
    );
    expect(graves.map((v) => v.id)).toEqual([]);
  });
});
