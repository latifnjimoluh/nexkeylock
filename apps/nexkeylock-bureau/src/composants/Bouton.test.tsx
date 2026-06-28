import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Bouton } from "./Bouton";

describe("Bouton", () => {
  it("affiche son libellé", () => {
    render(<Bouton>Déverrouiller</Bouton>);
    expect(screen.getByRole("button", { name: "Déverrouiller" })).toBeInTheDocument();
  });

  it("déclenche onClick", async () => {
    const onClick = vi.fn();
    render(<Bouton onClick={onClick}>Cliquer</Bouton>);
    await userEvent.click(screen.getByRole("button", { name: "Cliquer" }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("est inerte quand désactivé", async () => {
    const onClick = vi.fn();
    render(
      <Bouton disabled onClick={onClick}>
        Off
      </Bouton>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Off" }));
    expect(onClick).not.toHaveBeenCalled();
  });
});
