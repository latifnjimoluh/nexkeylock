import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { JaugeScore } from "./JaugeScore";

describe("JaugeScore", () => {
  it("affiche le score et une étiquette accessible", () => {
    render(<JaugeScore score={73} />);
    expect(screen.getByText("73")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /73 sur 100/ })).toBeInTheDocument();
  });

  it("borne les valeurs hors plage", () => {
    render(<JaugeScore score={150} />);
    expect(screen.getByText("100")).toBeInTheDocument();
  });
});
