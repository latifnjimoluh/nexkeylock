import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@testing-library/react";
import axe from "axe-core";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { EcranVerrouillage } from "../ecrans/EcranVerrouillage";

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue({ verrouille: true, existe: true, nombre_entrees: 0, a_recuperation: false });
});

describe("Accessibilité (axe)", () => {
  it("l'écran de verrouillage n'a pas de violation sérieuse", async () => {
    const { container } = render(<EcranVerrouillage />);
    const resultats = await axe.run(container);
    const graves = resultats.violations.filter(
      (v) => v.impact === "serious" || v.impact === "critical",
    );
    expect(graves).toEqual([]);
  });
});
