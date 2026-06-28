import { describe, it, expect } from "vitest";
import { estimerForce } from "./force";

describe("estimerForce", () => {
  it("renvoie vide pour une chaîne vide", () => {
    expect(estimerForce("")).toEqual({ bits: 0, niveau: "vide" });
  });

  it("juge faible un mot de passe court et simple", () => {
    expect(estimerForce("abc").niveau).toBe("faible");
  });

  it("juge excellent une longue phrase variée", () => {
    const f = estimerForce("Corr3ct-Cheval-Batterie-Agrafe!2026");
    expect(f.niveau).toBe("excellent");
    expect(f.bits).toBeGreaterThanOrEqual(100);
  });

  it("croît avec la taille du jeu de caractères", () => {
    const minuscules = estimerForce("aaaaaaaaaaaa").bits;
    const varie = estimerForce("aA1!aA1!aA1!").bits;
    expect(varie).toBeGreaterThan(minuscules);
  });
});
