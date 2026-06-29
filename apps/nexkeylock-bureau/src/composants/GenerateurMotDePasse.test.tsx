import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { GenerateurMotDePasse } from "./GenerateurMotDePasse";

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue({ valeur: "Abc123!xyzQ", entropieBits: 99 });
});

describe("GenerateurMotDePasse", () => {
  it("génère au montage et affiche l'entropie", async () => {
    render(<GenerateurMotDePasse />);
    expect(await screen.findByText("Abc123!xyzQ")).toBeInTheDocument();
    expect(screen.getByText(/99 bits/)).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("generer_mot_de_passe", expect.anything());
  });

  it("renvoie la valeur via « Utiliser »", async () => {
    const onUtiliser = vi.fn();
    render(<GenerateurMotDePasse onUtiliser={onUtiliser} />);
    await screen.findByText("Abc123!xyzQ");
    await userEvent.click(screen.getByRole("button", { name: "Utiliser" }));
    expect(onUtiliser).toHaveBeenCalledWith("Abc123!xyzQ");
  });

  it("renvoie la valeur via « Copier »", async () => {
    const onCopier = vi.fn();
    render(<GenerateurMotDePasse onCopier={onCopier} />);
    await screen.findByText("Abc123!xyzQ");
    await userEvent.click(screen.getByRole("button", { name: "Copier" }));
    expect(onCopier).toHaveBeenCalledWith("Abc123!xyzQ");
  });
});
