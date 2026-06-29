import { useEffect, useState, type FormEvent } from "react";
import { initialiserWasm, CoffrePwa } from "./lib/pont-wasm";
import { coffreExiste, lireCoffre, ecrireCoffre } from "./lib/stockage";
import * as sync from "./lib/synchro";

interface EntreeApercu {
  id: string;
  nom: string;
  nom_utilisateur: string | null;
  a_mot_de_passe: boolean;
  a_totp: boolean;
}

/**
 * PWA NexKeyLock (Jalon S5) : cœur WASM + IndexedDB + **synchronisation**.
 * Créer / déverrouiller / lister / révéler / ajouter / verrouiller, et se
 * synchroniser au serveur zéro-connaissance (même compte que l'app de bureau).
 *
 * Note : la parité complète d'écrans avec le bureau (édition détaillée, tableau
 * de bord, réglages riches) reste à étoffer ; l'essentiel — multi-appareils via
 * le même serveur — est opérationnel.
 */
export function App() {
  const [pret, setPret] = useState(false);
  const [existe, setExiste] = useState(false);
  const [coffre, setCoffre] = useState<CoffrePwa | null>(null);
  const [entrees, setEntrees] = useState<EntreeApercu[]>([]);
  const [motDePasse, setMotDePasse] = useState("");
  const [erreur, setErreur] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);
  const [reveles, setReveles] = useState<Record<string, string>>({});

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

  const reveler = (id: string) =>
    void agir(async () => {
      if (!coffre) return;
      setReveles((r) => ({ ...r, [id]: coffre.reveler(id, "mot_de_passe") }));
    });

  const verrouiller = () => {
    setCoffre(null);
    setReveles({});
  };

  if (!pret) {
    return <Centre>Chargement du cœur (WASM)…</Centre>;
  }

  if (coffre) {
    return (
      <main className="mx-auto flex w-full max-w-lg flex-col gap-4 p-6">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-semibold">Coffre déverrouillé</h1>
          <Bouton variante="secondaire" onClick={verrouiller}>
            Verrouiller
          </Bouton>
        </div>

        <section className="rounded-jeton border border-bordure bg-surface p-4 shadow-panneau">
          <p className="mb-2 text-sm text-texte-doux">
            {entrees.length} entrée(s) — cœur Rust en WASM.
          </p>
          <ul className="flex flex-col gap-1">
            {entrees.map((e) => (
              <li
                key={e.id}
                className="flex items-center justify-between gap-2 rounded px-2 py-1 text-sm"
              >
                <span className="min-w-0 flex-1 truncate text-texte">
                  {e.nom}
                  {e.nom_utilisateur ? ` — ${e.nom_utilisateur}` : ""}
                </span>
                {e.a_mot_de_passe &&
                  (reveles[e.id] ? (
                    <span className="select-all font-mono text-accent">{reveles[e.id]}</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => reveler(e.id)}
                      className="text-xs text-accent hover:underline"
                    >
                      Révéler
                    </button>
                  ))}
              </li>
            ))}
          </ul>
          <div className="mt-3">
            <Bouton onClick={ajouterExemple} disabled={occupe}>
              + Entrée de démo
            </Bouton>
          </div>
        </section>

        <PanneauSync coffre={coffre} onVerrouiller={verrouiller} />

        {erreur && (
          <p role="alert" className="rounded-jeton bg-danger/10 px-3 py-2 text-sm text-danger">
            {erreur}
          </p>
        )}
      </main>
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

function PanneauSync({ coffre, onVerrouiller }: { coffre: CoffrePwa; onVerrouiller: () => void }) {
  const [email, setEmail] = useState(sync.emailMemorise());
  const [motDePasse, setMotDePasse] = useState("");
  const [connecte, setConnecte] = useState(sync.connecte());
  const [conflit, setConflit] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);

  const agir = (action: () => Promise<void>) =>
    void (async () => {
      setOccupe(true);
      try {
        await action();
      } catch (e) {
        setMessage(typeof e === "string" ? e : "Opération impossible.");
      } finally {
        setOccupe(false);
        setMotDePasse("");
      }
    })();

  const requis = email.length > 0 && motDePasse.length > 0;

  return (
    <section className="rounded-jeton border border-bordure bg-surface p-4 shadow-panneau">
      <h2 className="mb-1 text-sm font-medium uppercase tracking-wide text-texte-doux">
        Synchronisation
      </h2>
      <p className="mb-3 text-xs text-texte-doux">
        Le serveur ne reçoit que le coffre chiffré + un identifiant ; jamais votre mot de passe.
      </p>
      <div className="flex flex-col gap-2">
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="email"
          aria-label="Email de synchronisation"
          className="rounded-jeton border border-bordure bg-surface-haute px-3 py-1.5 text-texte"
        />
        <input
          type="password"
          value={motDePasse}
          onChange={(e) => setMotDePasse(e.target.value)}
          placeholder="mot de passe maître"
          aria-label="Mot de passe (synchro)"
          className="rounded-jeton border border-bordure bg-surface-haute px-3 py-1.5 text-texte"
        />
      </div>
      <div className="mt-2 flex flex-wrap gap-2">
        <Bouton
          variante="secondaire"
          disabled={occupe || !requis}
          onClick={() =>
            agir(async () => {
              await sync.inscrire(email, motDePasse);
              setMessage("Compte créé.");
            })
          }
        >
          S'inscrire
        </Bouton>
        <Bouton
          disabled={occupe || !requis}
          onClick={() =>
            agir(async () => {
              await sync.connecter(email, motDePasse);
              setConnecte(true);
              setMessage("Connecté.");
            })
          }
        >
          Se connecter
        </Bouton>
      </div>
      {connecte && (
        <div className="mt-2 flex flex-wrap gap-2">
          <Bouton
            variante="secondaire"
            disabled={occupe}
            onClick={() =>
              agir(async () => {
                const r = await sync.pousser(coffre.octets());
                if (r.accepte) {
                  setConflit(false);
                  setMessage(`Envoyé (révision ${r.revision}).`);
                } else {
                  setConflit(true);
                  setMessage("Conflit : le coffre distant a changé.");
                }
              })
            }
          >
            Pousser
          </Bouton>
          <Bouton
            variante="secondaire"
            disabled={occupe}
            onClick={() =>
              agir(async () => {
                const { octets } = await sync.tirer();
                if (octets.length > 0) {
                  await ecrireCoffre(octets);
                  setMessage("Coffre distant récupéré — déverrouillez-le.");
                  onVerrouiller();
                } else {
                  setMessage("Rien à récupérer.");
                }
              })
            }
          >
            Tirer
          </Bouton>
        </div>
      )}
      {conflit && (
        <div className="mt-2 flex gap-2">
          <Bouton
            variante="danger"
            disabled={occupe}
            onClick={() =>
              agir(async () => {
                const r = await sync.forcer(coffre.octets());
                if (r.accepte) {
                  setConflit(false);
                  setMessage(`Version locale imposée (révision ${r.revision}).`);
                }
              })
            }
          >
            Forcer (garder local)
          </Bouton>
        </div>
      )}
      {message && <p className="mt-2 text-xs text-texte-doux">{message}</p>}
    </section>
  );
}

function Centre({ children }: { children: React.ReactNode }) {
  return <main className="flex min-h-full items-center justify-center p-6">{children}</main>;
}

function Bouton({
  children,
  variante = "primaire",
  ...reste
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variante?: "primaire" | "secondaire" | "danger";
}) {
  const styles =
    variante === "primaire"
      ? "bg-accent text-accent-contraste"
      : variante === "danger"
        ? "bg-danger text-white"
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
