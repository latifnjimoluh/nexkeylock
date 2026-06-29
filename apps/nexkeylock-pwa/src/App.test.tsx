import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// Le WASM et IndexedDB ne tournent pas sous jsdom : on les simule pour valider
// le flux React (le cœur lui-même est testé en natif dans nex-coffre).
vi.mock("./lib/pont-wasm", () => ({
  initialiserWasm: vi.fn().mockResolvedValue(undefined),
  CoffrePwa: { creer: vi.fn(), ouvrir: vi.fn() },
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
