import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useVerrouillageAuto } from "./verrouillageAuto";

describe("useVerrouillageAuto", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("verrouille après le délai d'inactivité", () => {
    const onV = vi.fn();
    renderHook(() => useVerrouillageAuto(1, onV, true));
    act(() => vi.advanceTimersByTime(60_000));
    expect(onV).toHaveBeenCalledTimes(1);
  });

  it("réinitialise le minuteur sur activité", () => {
    const onV = vi.fn();
    renderHook(() => useVerrouillageAuto(1, onV, true));
    act(() => vi.advanceTimersByTime(50_000));
    act(() => window.dispatchEvent(new Event("mousemove")));
    act(() => vi.advanceTimersByTime(50_000));
    expect(onV).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(10_000));
    expect(onV).toHaveBeenCalledTimes(1);
  });

  it("verrouille immédiatement en arrière-plan", () => {
    const onV = vi.fn();
    renderHook(() => useVerrouillageAuto(60, onV, true));
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    expect(onV).toHaveBeenCalledTimes(1);
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
  });

  it("ne fait rien si inactif", () => {
    const onV = vi.fn();
    renderHook(() => useVerrouillageAuto(1, onV, false));
    act(() => vi.advanceTimersByTime(120_000));
    expect(onV).not.toHaveBeenCalled();
  });
});
