import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { EcranTableauBord } from "./EcranTableauBord";

const RAPPORT = {
  faibles: [{ id: "1", nom: "Banque" }],
  reutilises: [],
  anciens: [],
  totalAvecMotDePasse: 1,
  score: 60,
};

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "lancer_audit") return Promise.resolve(RAPPORT);
    if (cmd === "verifier_fuites")
      return Promise.resolve([{ id: "1", nom: "Banque", occurrences: 5 }]);
    return Promise.resolve(null);
  });
});

describe("EcranTableauBord", () => {
  it("affiche le score et les constats, et ouvre une entrée au clic", async () => {
    const onOuvrir = vi.fn();
    render(<EcranTableauBord onOuvrirEntree={onOuvrir} onToast={vi.fn()} />);

    expect(await screen.findByText("60")).toBeInTheDocument();
    // L'entrée faible « Banque » est cliquable et déclenche l'ouverture.
    await userEvent.click(screen.getByRole("button", { name: "Banque" }));
    expect(onOuvrir).toHaveBeenCalledWith("1");
  });

  it("lance la vérification de fuites à la demande (opt-in)", async () => {
    render(<EcranTableauBord onOuvrirEntree={vi.fn()} onToast={vi.fn()} />);
    await screen.findByText("60");
    // Aucune requête de fuite tant qu'on ne clique pas.
    expect(invoke).not.toHaveBeenCalledWith("verifier_fuites");

    await userEvent.click(screen.getByRole("button", { name: "Vérifier les fuites" }));
    expect(await screen.findByText(/5\D*fuites/)).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("verifier_fuites");
  });
});
