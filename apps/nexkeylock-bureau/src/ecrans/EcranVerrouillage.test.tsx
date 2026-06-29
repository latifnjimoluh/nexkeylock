import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

import { EcranVerrouillage } from "./EcranVerrouillage";

const APERCU = { verrouille: false, existe: true, nombre_entrees: 0, a_recuperation: false };

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "fichier_cle_requise") return Promise.resolve(false);
    return Promise.resolve(APERCU);
  });
});

describe("EcranVerrouillage", () => {
  it("envoie le mot de passe au backend lors du déverrouillage", async () => {
    render(<EcranVerrouillage />);
    await userEvent.type(screen.getByLabelText("Mot de passe maître"), "ouvre-toi");
    await userEvent.click(screen.getByRole("button", { name: "Déverrouiller" }));

    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith(
        "deverrouiller",
        expect.objectContaining({ motDePasse: "ouvre-toi" }),
      ),
    );
  });

  it("affiche une erreur neutre sur mauvais mot de passe", async () => {
    invoke.mockImplementation((cmd: string) => {
      if (cmd === "fichier_cle_requise") return Promise.resolve(false);
      return Promise.reject({ code: "mot_de_passe", message: "Mot de passe maître incorrect." });
    });
    render(<EcranVerrouillage />);
    await userEvent.type(screen.getByLabelText("Mot de passe maître"), "mauvais");
    await userEvent.click(screen.getByRole("button", { name: "Déverrouiller" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Mot de passe maître incorrect.");
  });

  it("exige un fichier-clé quand le coffre en demande un", async () => {
    invoke.mockImplementation((cmd: string) => {
      if (cmd === "fichier_cle_requise") return Promise.resolve(true);
      return Promise.resolve(APERCU);
    });
    render(<EcranVerrouillage />);
    await userEvent.type(screen.getByLabelText("Mot de passe maître"), "secret");
    // Tant que le fichier-clé n'est pas choisi, le déverrouillage est bloqué.
    expect(
      await screen.findByRole("button", { name: "Choisir le fichier-clé…" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Déverrouiller" })).toBeDisabled();
  });
});
