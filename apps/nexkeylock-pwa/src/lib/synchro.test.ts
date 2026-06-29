import { describe, it, expect, vi, beforeEach } from "vitest";

// hash_auth est dans le WASM (testé en natif) ; on le simule ici.
vi.mock("./pont-wasm", () => ({ hash_auth: () => "abcd1234" }));

import * as sync from "./synchro";

beforeEach(() => {
  localStorage.clear();
});

describe("client de synchro PWA", () => {
  it("inscrit et se connecte (jeton mémorisé)", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 201 })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ jeton: "T" }) });
    vi.stubGlobal("fetch", fetchMock);

    await sync.inscrire("a@b.fr", "mdp");
    await sync.connecter("a@b.fr", "mdp");

    expect(sync.connecte()).toBe(true);
    expect(sync.emailMemorise()).toBe("a@b.fr");
    expect(fetchMock).toHaveBeenCalledWith(
      "/sync/inscription",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("inscription en double => erreur", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 409 }));
    await expect(sync.inscrire("a@b.fr", "mdp")).rejects.toContain("existe déjà");
  });

  it("pousser : accepté puis conflit", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ jeton: "T" }) }),
    );
    await sync.connecter("a@b.fr", "mdp");

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ revision: 1 }) }),
    );
    expect(await sync.pousser(new Uint8Array([1, 2, 3]))).toEqual({ accepte: true, revision: 1 });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 409, json: async () => ({ actuelle: 5 }) }),
    );
    expect(await sync.pousser(new Uint8Array([1]))).toEqual({ accepte: false, revision: 5 });
  });
});
