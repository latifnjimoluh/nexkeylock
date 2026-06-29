import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn(), open: vi.fn() }));

import { EcranReglages } from "./EcranReglages";

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "obtenir_reglages")
      return Promise.resolve({ delaiAutoLockMin: 5, delaiPressePapiersS: 20 });
    if (cmd === "obtenir_kdf")
      return Promise.resolve({ memoireKio: 262144, iterations: 3, parallelisme: 4 });
    if (cmd === "version_coeur") return Promise.resolve("0.2.0");
    return Promise.resolve(null);
  });
});

describe("EcranReglages", () => {
  it("change le mot de passe maître via le backend", async () => {
    render(<EcranReglages onToast={vi.fn()} onCoffreChange={vi.fn()} />);

    await userEvent.type(screen.getByLabelText("Mot de passe actuel"), "ancien");
    await userEvent.type(screen.getByLabelText("Nouveau mot de passe"), "nouveau-mdp");
    await userEvent.type(screen.getByLabelText("Confirmer"), "nouveau-mdp");
    await userEvent.click(screen.getByRole("button", { name: "Changer le mot de passe" }));

    await waitFor(() =>
      expect(invoke).toHaveBeenCalledWith("changer_mot_de_passe", {
        actuel: "ancien",
        nouveau: "nouveau-mdp",
      }),
    );
  });

  it("affiche les paramètres KDF (mémoire en Mio)", async () => {
    render(<EcranReglages onToast={vi.fn()} onCoffreChange={vi.fn()} />);
    expect(await screen.findByText(/256 Mio/)).toBeInTheDocument();
  });
});
