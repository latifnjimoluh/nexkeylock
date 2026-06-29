import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

import { EcranVerrouillage } from "../ecrans/EcranVerrouillage";

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "fichier_cle_requise") return Promise.resolve(false);
    return Promise.resolve({
      verrouille: false,
      existe: true,
      nombre_entrees: 0,
      a_recuperation: false,
    });
  });
  localStorage.clear();
  sessionStorage.clear();
});

describe("Sécurité : aucun secret en stockage navigateur", () => {
  it("le déverrouillage ne persiste pas le mot de passe maître", async () => {
    const secret = "MotDePasseMaitreSuperSecret-2026";
    render(<EcranVerrouillage />);
    await userEvent.type(screen.getByLabelText("Mot de passe maître"), secret);
    await userEvent.click(screen.getByRole("button", { name: "Déverrouiller" }));
    await waitFor(() => expect(invoke).toHaveBeenCalled());

    // sessionStorage doit rester vide ; aucune valeur de localStorage ne doit
    // contenir le secret (seule la préférence de thème peut y figurer).
    expect(sessionStorage.length).toBe(0);
    for (let i = 0; i < localStorage.length; i++) {
      const cle = localStorage.key(i);
      if (cle) {
        expect(localStorage.getItem(cle)).not.toContain(secret);
      }
    }
  });
});
