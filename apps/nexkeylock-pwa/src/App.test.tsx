import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// Le cœur vit dans un Web Worker (indisponible sous jsdom) : on le simule.
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

describe("App (PWA)", () => {
  it("propose de créer un coffre quand aucun n'existe", async () => {
    render(<App />);
    expect(await screen.findByRole("button", { name: "Créer le coffre" })).toBeInTheDocument();
    expect(screen.getByLabelText("Mot de passe maître")).toBeInTheDocument();
  });
});
