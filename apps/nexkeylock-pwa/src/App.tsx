import { useEffect, useState, type FormEvent } from "react";
import { initialiserWasm, CoffrePwa } from "./lib/pont-wasm";
import { coffreExiste, lireCoffre, ecrireCoffre } from "./lib/stockage";

interface EntreeApercu {
  id: string;
  nom: string;
  nom_utilisateur: string | null;
  a_mot_de_passe: boolean;
  a_totp: boolean;
}

/**
 * Squelette de la PWA (Jalon S4) : prouve la chaîne complète cœur WASM +
 * IndexedDB (créer / déverrouiller / lister / ajouter / verrouiller). Les écrans
 * complets (réutilisant les composants du bureau) arrivent au Jalon S5.
 */
export function App() {
  const [pret, setPret] = useState(false);
  const [existe, setExiste] = useState(false);
  const [coffre, setCoffre] = useState<CoffrePwa | null>(null);
  const [entrees, setEntrees] = useState<EntreeApercu[]>([]);
  const [motDePasse, setMotDePasse] = useState("");
  const [erreur, setErreur] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);

  useEffect(() => {
    void (async () => {
      await initialiserWasm();
      setExiste(await coffreExiste());
      setPret(true);
    })();
  }, []);

  const rafraichir = (c: CoffrePwa) => {
    setEntrees(JSON.parse(c.lister()) as EntreeApercu[]);
  };

  const persister = async (c: CoffrePwa) => {
    await ecrireCoffre(c.octets());
  };

  const agir = async (action: () => Promise<void>) => {
    setErreur(null);
    setOccupe(true);
    try {
      await action();
    } catch (e) {
      setErreur(typeof e === "string" ? e : "Opération impossible.");
    } finally {
      setOccupe(false);
      setMotDePasse("");
    }
  };

  const creer = (e: FormEvent) => {
    e.preventDefault();
    void agir(async () => {
      const c = CoffrePwa.creer(motDePasse, undefined);
      await persister(c);
      setCoffre(c);
      setExiste(true);
      rafraichir(c);
    });
  };

  const ouvrir = (e: FormEvent) => {
    e.preventDefault();
    void agir(async () => {
      const octets = await lireCoffre();
      if (!octets) throw "aucun coffre";
      const c = CoffrePwa.ouvrir(octets, motDePasse, undefined);
      setCoffre(c);
      rafraichir(c);
    });
  };

  const ajouterExemple = () =>
    void agir(async () => {
      if (!coffre) return;
      const donnees = JSON.stringify({ nom: "Exemple", mot_de_passe: "secret-démo" });
      coffre.ajouter(donnees, BigInt(Math.floor(Date.now() / 1000)));
      await persister(coffre);
      rafraichir(coffre);
    });

  if (!pret) {
    return <Centre>Chargement du cœur (WASM)…</Centre>;
  }

  if (coffre) {
    return (
      <Centre>
        <div className="w-full max-w-md rounded-jeton border border-bordure bg-surface p-6 shadow-panneau">
          <h1 className="mb-1 text-xl font-semibold">Coffre déverrouillé</h1>
          <p className="mb-4 text-sm text-texte-doux">
            {entrees.length} entrée(s) — cœur Rust en WASM.
          </p>
          <ul className="mb-4 flex flex-col gap-1">
            {entrees.map((e) => (
              <li key={e.id} className="rounded px-2 py-1 text-sm text-texte">
                {e.nom}
                {e.nom_utilisateur ? ` — ${e.nom_utilisateur}` : ""}
              </li>
            ))}
          </ul>
          <div className="flex gap-2">
            <Bouton onClick={ajouterExemple} disabled={occupe}>
              + Entrée de démo
            </Bouton>
            <Bouton variante="secondaire" onClick={() => setCoffre(null)}>
              Verrouiller
            </Bouton>
          </div>
        </div>
      </Centre>
    );
  }

  return (
    <Centre>
      <form
        onSubmit={existe ? ouvrir : creer}
        className="flex w-full max-w-sm flex-col gap-4 rounded-jeton border border-bordure bg-surface p-8 shadow-panneau"
      >
        <div className="text-center">
          <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-jeton bg-accent text-xl text-accent-contraste">
            🔒
          </div>
          <h1 className="text-xl font-semibold">NexKeyLock</h1>
          <p className="text-sm text-texte-doux">
            {existe ? "Déverrouillez votre coffre" : "Créez votre coffre"}
          </p>
        </div>
        <input
          type="password"
          value={motDePasse}
          onChange={(ev) => setMotDePasse(ev.target.value)}
          placeholder="Mot de passe maître"
          aria-label="Mot de passe maître"
          autoFocus
          className="rounded-jeton border border-bordure bg-surface-haute px-3 py-2 font-mono text-texte"
        />
        {erreur && (
          <p role="alert" className="rounded-jeton bg-danger/10 px-3 py-2 text-sm text-danger">
            {erreur}
          </p>
        )}
        <Bouton type="submit" disabled={occupe || motDePasse.length === 0}>
          {occupe ? "…" : existe ? "Déverrouiller" : "Créer le coffre"}
        </Bouton>
        <p className="text-center text-xs text-texte-doux">
          Note : Argon2id (256 Mio) s'exécute dans le navigateur — quelques secondes.
        </p>
      </form>
    </Centre>
  );
}

function Centre({ children }: { children: React.ReactNode }) {
  return <main className="flex min-h-full items-center justify-center p-6">{children}</main>;
}

function Bouton({
  children,
  variante = "primaire",
  ...reste
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variante?: "primaire" | "secondaire" }) {
  const styles =
    variante === "primaire"
      ? "bg-accent text-accent-contraste"
      : "bg-surface-haute text-texte border border-bordure";
  return (
    <button
      {...reste}
      className={`rounded-jeton px-4 py-2 text-sm font-medium transition disabled:opacity-50 ${styles}`}
    >
      {children}
    </button>
  );
}
