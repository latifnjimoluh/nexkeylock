import { useEffect, useState } from "react";
import { save, open } from "@tauri-apps/plugin-dialog";
import { SelecteurTheme } from "../composants/SelecteurTheme";
import { Bouton } from "../composants/Bouton";
import { ChampMotDePasse } from "../composants/ChampMotDePasse";
import {
  obtenirReglages,
  definirReglages,
  changerMotDePasse,
  exporterCoffre,
  importerCoffre,
  obtenirKdf,
  verifierMaj,
  versionCoeur,
  estErreurCommande,
  synchroInscrire,
  synchroConnecter,
  synchroPousser,
  synchroForcer,
  synchroTirer,
  type Reglages,
  type ParametresKdf,
} from "../lib/pont";

interface Proprietes {
  onToast: (message: string) => void;
  /** Appelé après un import (le coffre est verrouillé → rafraîchir l'état). */
  onCoffreChange: () => void;
}

const FILTRE = [{ name: "Coffre NexKeyLock", extensions: ["vault"] }];

/** Écran des réglages : préférences, mot de passe maître, sauvegarde, à propos. */
export function EcranReglages({ onToast, onCoffreChange }: Proprietes) {
  const [reglages, setReglages] = useState<Reglages | null>(null);
  const [kdf, setKdf] = useState<ParametresKdf | null>(null);
  const [version, setVersion] = useState<string>("…");

  useEffect(() => {
    obtenirReglages()
      .then(setReglages)
      .catch(() => onToast("Réglages illisibles."));
    obtenirKdf()
      .then(setKdf)
      .catch(() => undefined);
    versionCoeur()
      .then(setVersion)
      .catch(() => undefined);
  }, [onToast]);

  const majReglage = async (champ: keyof Reglages, valeur: number) => {
    if (!reglages || valeur < 1) return;
    const suivant = { ...reglages, [champ]: valeur };
    setReglages(suivant);
    try {
      await definirReglages(suivant);
    } catch {
      onToast("Enregistrement des réglages impossible.");
    }
  };

  return (
    <main className="mx-auto flex w-full max-w-2xl flex-col gap-6 p-8">
      <h1 className="text-xl font-semibold text-texte">Réglages</h1>

      <Section titre="Apparence">
        <Ligne libelle="Thème">
          <SelecteurTheme />
        </Ligne>
      </Section>

      <Section titre="Sécurité de session">
        <Ligne libelle="Verrouillage automatique (minutes d'inactivité)">
          <ChampNombre
            valeur={reglages?.delaiAutoLockMin ?? 5}
            min={1}
            max={120}
            onValeur={(v) => void majReglage("delaiAutoLockMin", v)}
          />
        </Ligne>
        <Ligne libelle="Effacement du presse-papiers (secondes)">
          <ChampNombre
            valeur={reglages?.delaiPressePapiersS ?? 20}
            min={1}
            max={300}
            onValeur={(v) => void majReglage("delaiPressePapiersS", v)}
          />
        </Ligne>
      </Section>

      <ChangementMotDePasse onToast={onToast} />

      <Section titre="Sauvegarde chiffrée">
        <p className="text-sm text-texte-doux">
          L'export copie votre coffre <strong>déjà chiffré</strong> (le mot de passe maître reste
          requis pour l'ouvrir). L'import remplace le coffre courant puis le verrouille.
        </p>
        <div className="flex gap-2">
          <Bouton
            variante="secondaire"
            onClick={() =>
              void (async () => {
                try {
                  const chemin = await save({
                    defaultPath: "nexkeylock-export.vault",
                    filters: FILTRE,
                  });
                  if (chemin) {
                    await exporterCoffre(chemin);
                    onToast("Coffre exporté.");
                  }
                } catch (e) {
                  onToast(estErreurCommande(e) ? e.message : "Export impossible.");
                }
              })()
            }
          >
            Exporter…
          </Bouton>
          <Bouton
            variante="secondaire"
            onClick={() =>
              void (async () => {
                try {
                  const sel = await open({ multiple: false, filters: FILTRE });
                  if (typeof sel === "string") {
                    await importerCoffre(sel);
                    onToast("Coffre importé — déverrouillez-le.");
                    onCoffreChange();
                  }
                } catch (e) {
                  onToast(estErreurCommande(e) ? e.message : "Import impossible.");
                }
              })()
            }
          >
            Importer…
          </Bouton>
        </div>
      </Section>

      <Section titre="Avancé (KDF)">
        {kdf ? (
          <p className="font-mono text-sm text-texte-doux">
            Argon2id — mémoire {Math.round(kdf.memoireKio / 1024)} Mio, {kdf.iterations}{" "}
            itération(s), parallélisme {kdf.parallelisme}.
          </p>
        ) : (
          <p className="text-sm text-texte-doux">Paramètres indisponibles.</p>
        )}
        <p className="text-xs text-texte-doux">
          Déverrouillage biométrique (Windows Hello) : <strong>prévu</strong> — non encore relié au
          coffre-fort matériel de l'OS. Désactivé pour ne rien promettre de faux.
        </p>
      </Section>

      <Synchronisation reglages={reglages} onToast={onToast} onCoffreChange={onCoffreChange} />

      <APropos version={version} onToast={onToast} />
    </main>
  );
}

function ChangementMotDePasse({ onToast }: { onToast: (m: string) => void }) {
  const [actuel, setActuel] = useState("");
  const [nouveau, setNouveau] = useState("");
  const [confirme, setConfirme] = useState("");
  const [occupe, setOccupe] = useState(false);

  const valide = actuel.length > 0 && nouveau.length >= 8 && nouveau === confirme;

  const soumettre = async () => {
    if (!valide || occupe) return;
    setOccupe(true);
    try {
      await changerMotDePasse(actuel, nouveau);
      setActuel("");
      setNouveau("");
      setConfirme("");
      onToast("Mot de passe maître changé.");
    } catch (e) {
      onToast(estErreurCommande(e) ? e.message : "Changement impossible.");
    } finally {
      setOccupe(false);
    }
  };

  return (
    <Section titre="Mot de passe maître">
      <ChampMotDePasse etiquette="Mot de passe actuel" valeur={actuel} onValeur={setActuel} />
      <ChampMotDePasse etiquette="Nouveau mot de passe" valeur={nouveau} onValeur={setNouveau} />
      <ChampMotDePasse etiquette="Confirmer" valeur={confirme} onValeur={setConfirme} />
      {confirme.length > 0 && nouveau !== confirme && (
        <p className="text-xs text-danger">Les mots de passe ne correspondent pas.</p>
      )}
      <Bouton onClick={() => void soumettre()} disabled={!valide || occupe}>
        {occupe ? "Changement…" : "Changer le mot de passe"}
      </Bouton>
    </Section>
  );
}

function Synchronisation({
  reglages,
  onToast,
  onCoffreChange,
}: {
  reglages: Reglages | null;
  onToast: (m: string) => void;
  onCoffreChange: () => void;
}) {
  const [serveur, setServeur] = useState("");
  const [email, setEmail] = useState("");
  const [motDePasse, setMotDePasse] = useState("");
  const [conflit, setConflit] = useState(false);
  const [occupe, setOccupe] = useState(false);

  // Pré-remplit depuis les réglages chargés.
  useEffect(() => {
    if (reglages) {
      setServeur(reglages.serveurSync ?? "http://127.0.0.1:8787");
      setEmail(reglages.emailSync ?? "");
    }
  }, [reglages]);

  const lancer = async (action: () => Promise<void>) => {
    setOccupe(true);
    try {
      await action();
    } catch (e) {
      onToast(estErreurCommande(e) ? e.message : "Opération de synchronisation impossible.");
    } finally {
      setOccupe(false);
    }
  };

  const requis = serveur.length > 0 && email.length > 0 && motDePasse.length > 0;

  return (
    <Section titre="Synchronisation (zéro-connaissance)">
      <p className="text-sm text-texte-doux">
        Le serveur ne reçoit que votre coffre <strong>chiffré</strong> et un identifiant
        d'authentification ; jamais votre mot de passe ni vos données.
      </p>
      <Ligne libelle="Serveur">
        <input
          value={serveur}
          onChange={(e) => setServeur(e.target.value)}
          placeholder="http://127.0.0.1:8787"
          className="w-64 rounded-jeton border border-bordure bg-surface px-3 py-1.5 text-texte"
        />
      </Ligne>
      <Ligne libelle="Email du compte">
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-64 rounded-jeton border border-bordure bg-surface px-3 py-1.5 text-texte"
        />
      </Ligne>
      <ChampMotDePasse
        etiquette="Mot de passe maître (pour s'authentifier)"
        valeur={motDePasse}
        onValeur={setMotDePasse}
      />

      <div className="flex flex-wrap gap-2">
        <Bouton
          variante="secondaire"
          disabled={occupe || !requis}
          onClick={() =>
            void lancer(async () => {
              await synchroInscrire(serveur, email, motDePasse);
              onToast("Compte créé sur le serveur.");
            })
          }
        >
          S'inscrire
        </Bouton>
        <Bouton
          disabled={occupe || !requis}
          onClick={() =>
            void lancer(async () => {
              await synchroConnecter(serveur, email, motDePasse);
              setMotDePasse("");
              onToast("Connecté à la synchronisation.");
            })
          }
        >
          Se connecter
        </Bouton>
      </div>

      <div className="flex flex-wrap gap-2">
        <Bouton
          variante="secondaire"
          disabled={occupe}
          onClick={() =>
            void lancer(async () => {
              const r = await synchroPousser();
              if (r.accepte) {
                setConflit(false);
                onToast(`Coffre envoyé (révision ${r.revision}).`);
              } else {
                setConflit(true);
                onToast("Conflit : le coffre distant a changé.");
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
            void lancer(async () => {
              const r = await synchroTirer();
              if (r.recupere) {
                onToast("Coffre distant récupéré — déverrouillez-le.");
                onCoffreChange();
              } else {
                onToast("Rien à récupérer sur le serveur.");
              }
            })
          }
        >
          Tirer
        </Bouton>
      </div>

      {conflit && (
        <div className="rounded-jeton bg-alerte/10 p-3 text-sm">
          <p className="mb-2 text-alerte">
            Conflit détecté. Choisissez : garder votre version locale (forcer) ou récupérer la
            version distante (vos changements locaux non envoyés seront perdus).
          </p>
          <div className="flex gap-2">
            <Bouton
              variante="danger"
              disabled={occupe}
              onClick={() =>
                void lancer(async () => {
                  const r = await synchroForcer();
                  if (r.accepte) {
                    setConflit(false);
                    onToast(`Version locale imposée (révision ${r.revision}).`);
                  }
                })
              }
            >
              Forcer (garder local)
            </Bouton>
            <Bouton
              variante="secondaire"
              disabled={occupe}
              onClick={() =>
                void lancer(async () => {
                  const r = await synchroTirer();
                  if (r.recupere) {
                    setConflit(false);
                    onToast("Version distante récupérée — déverrouillez-le.");
                    onCoffreChange();
                  }
                })
              }
            >
              Tirer (récupérer distant)
            </Bouton>
          </div>
        </div>
      )}
    </Section>
  );
}

function APropos({ version, onToast }: { version: string; onToast: (m: string) => void }) {
  const [maj, setMaj] = useState<string | null>(null);

  const verifier = async () => {
    try {
      const info = await verifierMaj();
      setMaj(
        info.disponible
          ? `Mise à jour disponible : ${info.derniere ?? "?"}`
          : "Vous avez la dernière version.",
      );
    } catch {
      onToast("Vérification de mise à jour indisponible.");
    }
  };

  return (
    <Section titre="À propos">
      <p className="text-sm text-texte-doux">
        NexKeyLock <span className="font-mono text-texte">{version}</span> — chiffrement local de
        bout en bout (Argon2id, XChaCha20-Poly1305). Aucune donnée ne quitte l'appareil sans action
        explicite.
      </p>
      <div className="flex items-center gap-3">
        <Bouton variante="secondaire" onClick={() => void verifier()}>
          Vérifier les mises à jour
        </Bouton>
        {maj && <span className="text-sm text-texte-doux">{maj}</span>}
      </div>
    </Section>
  );
}

function Section({ titre, children }: { titre: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3 rounded-jeton border border-bordure bg-surface p-6">
      <h2 className="text-sm font-medium uppercase tracking-wide text-texte-doux">{titre}</h2>
      {children}
    </section>
  );
}

function Ligne({ libelle, children }: { libelle: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-sm text-texte">{libelle}</span>
      {children}
    </div>
  );
}

function ChampNombre({
  valeur,
  min,
  max,
  onValeur,
}: {
  valeur: number;
  min: number;
  max: number;
  onValeur: (v: number) => void;
}) {
  return (
    <input
      type="number"
      value={valeur}
      min={min}
      max={max}
      onChange={(e) => onValeur(Number(e.target.value))}
      aria-label="valeur"
      className="w-24 rounded-jeton border border-bordure bg-surface px-3 py-1.5 text-right text-texte"
    />
  );
}
