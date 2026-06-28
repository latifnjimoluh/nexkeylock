import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Mock du pont Tauri : on contrôle la commande `invoke`.
const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { EcranVerrouillage } from "./EcranVerrouillage";

beforeEach(() => {
  invoke.mockReset();
});

describe("EcranVerrouillage", () => {
  it("envoie le mot de passe au backend lors du déverrouillage", async () => {
    invoke.mockResolvedValue({
      verrouille: false,
      existe: true,
      nombre_entrees: 0,
      a_recuperation: false,
    });
    render(<EcranVerrouillage />);
    await userEvent.type(screen.getByLabelText("Mot de passe maître"), "ouvre-toi");
    await userEvent.click(screen.getByRole("button", { name: "Déverrouiller" }));

    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("deverrouiller", { motDePasse: "ouvre-toi" }),
    );
  });

  it("affiche une erreur neutre sur mauvais mot de passe", async () => {
    invoke.mockRejectedValue({ code: "mot_de_passe", message: "Mot de passe maître incorrect." });
    render(<EcranVerrouillage />);
    await userEvent.type(screen.getByLabelText("Mot de passe maître"), "mauvais");
    await userEvent.click(screen.getByRole("button", { name: "Déverrouiller" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Mot de passe maître incorrect.");
  });
});
