import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { FormulaireEntree } from "./FormulaireEntree";

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue("nouvel-id");
});

describe("FormulaireEntree", () => {
  it("crée une entrée avec les données saisies", async () => {
    const onEnregistre = vi.fn();
    const onFerme = vi.fn();
    render(<FormulaireEntree onFerme={onFerme} onEnregistre={onEnregistre} />);

    await userEvent.type(screen.getByLabelText("Nom"), "GitHub");
    await userEvent.type(screen.getByLabelText("Mot de passe"), "motdepasse-fort");
    await userEvent.click(screen.getByRole("button", { name: "Enregistrer" }));

    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith(
        "ajouter_entree",
        expect.objectContaining({
          donnees: expect.objectContaining({ nom: "GitHub", motDePasse: "motdepasse-fort" }),
        }),
      ),
    );
    expect(onEnregistre).toHaveBeenCalled();
    expect(onFerme).toHaveBeenCalled();
  });

  it("n'enregistre pas sans nom", async () => {
    render(<FormulaireEntree onFerme={vi.fn()} onEnregistre={vi.fn()} />);
    expect(screen.getByRole("button", { name: "Enregistrer" })).toBeDisabled();
  });
});
