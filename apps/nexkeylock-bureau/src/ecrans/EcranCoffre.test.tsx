import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { EcranCoffre } from "./EcranCoffre";

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation((cmd: string) => {
    if (cmd === "lister_entrees") {
      return Promise.resolve([
        {
          id: "1",
          nom: "GitHub",
          nom_utilisateur: "moi@exemple.fr",
          uris: ["https://github.com"],
          categorie: "connexion",
          a_mot_de_passe: true,
          a_totp: false,
        },
      ]);
    }
    if (cmd === "reveler_champ") return Promise.resolve("s3cr3t-révélé");
    return Promise.resolve(null);
  });
});

describe("EcranCoffre", () => {
  it("liste les entrées, sélectionne et révèle le mot de passe à la demande", async () => {
    render(<EcranCoffre />);

    // L'entrée apparaît dans la liste.
    const carte = await screen.findByRole("button", { name: /GitHub/ });
    await userEvent.click(carte);

    // Le mot de passe n'est pas révélé par défaut.
    expect(screen.queryByText("s3cr3t-révélé")).not.toBeInTheDocument();

    // Après « Afficher », il est révélé via le backend.
    await userEvent.click(screen.getByRole("button", { name: "Afficher" }));
    expect(await screen.findByText("s3cr3t-révélé")).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("reveler_champ", { id: "1", champ: "mot_de_passe" });
  });
});
