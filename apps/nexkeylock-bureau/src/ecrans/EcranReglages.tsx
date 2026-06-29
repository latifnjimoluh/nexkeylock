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
