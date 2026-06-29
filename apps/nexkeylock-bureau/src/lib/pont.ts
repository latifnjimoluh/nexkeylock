/**
 * Pont vers le backend Tauri (couche de commandes).
 *
 * Toute la logique sensible vit côté Rust ; ce module ne fait qu'invoquer les
 * commandes et typer leurs résultats. Aucun secret n'est mis en cache ici.
 */
import { invoke } from "@tauri-apps/api/core";

/** Métadonnées renvoyées par le backend (jamais de secret). */
export interface Apercu {
  verrouille: boolean;
  existe: boolean;
  nombreEntrees: number;
  aRecuperation: boolean;
}

/** Erreur structurée renvoyée par une commande. */
export interface ErreurCommande {
  code: string;
  message: string;
}

/** Vrai si l'objet ressemble à une ErreurCommande. */
export function estErreurCommande(e: unknown): e is ErreurCommande {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

// Le backend sérialise en snake_case ; on normalise vers camelCase.
interface ApercuBrut {
  verrouille: boolean;
  existe: boolean;
  nombre_entrees: number;
  a_recuperation: boolean;
}

function normaliser(a: ApercuBrut): Apercu {
  return {
    verrouille: a.verrouille,
    existe: a.existe,
    nombreEntrees: a.nombre_entrees,
    aRecuperation: a.a_recuperation,
  };
}

/** Version du cœur (nex-coffre). */
export function versionCoeur(): Promise<string> {
  return invoke<string>("version_coeur");
}

/** Indique si un fichier de coffre existe déjà. */
export function coffreExiste(): Promise<boolean> {
  return invoke<boolean>("coffre_existe");
}

/** État courant (métadonnées). */
export async function etat(): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("etat"));
}

/** Crée un nouveau coffre (laisse le coffre déverrouillé). */
export async function creerCoffre(motDePasse: string): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("creer_coffre", { motDePasse }));
}

/** Déverrouille le coffre avec le mot de passe maître. */
export async function deverrouiller(motDePasse: string): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("deverrouiller", { motDePasse }));
}

/** Verrouille le coffre (efface les clés côté backend). */
export async function verrouiller(): Promise<Apercu> {
  return normaliser(await invoke<ApercuBrut>("verrouiller"));
}

/** Configure un code de récupération et le renvoie (à afficher une seule fois). */
export function configurerRecuperation(): Promise<string> {
  return invoke<string>("configurer_recuperation");
}

/** Métadonnées d'une entrée (jamais de secret). */
export interface EntreeApercu {
  id: string;
  nom: string;
  nomUtilisateur: string | null;
  uris: string[];
  categorie: string;
  aMotDePasse: boolean;
  aTotp: boolean;
}

interface EntreeApercuBrut {
  id: string;
  nom: string;
  nom_utilisateur: string | null;
  uris: string[];
  categorie: string;
  a_mot_de_passe: boolean;
  a_totp: boolean;
}

function normaliserEntree(e: EntreeApercuBrut): EntreeApercu {
  return {
    id: e.id,
    nom: e.nom,
    nomUtilisateur: e.nom_utilisateur,
    uris: e.uris,
    categorie: e.categorie,
    aMotDePasse: e.a_mot_de_passe,
    aTotp: e.a_totp,
  };
}

/** Code TOTP courant et temps de validité restant. */
export interface CodeTotp {
  code: string;
  secondesRestantes: number;
}

/** Liste les entrées (métadonnées), filtrées par `requete`. */
export async function listerEntrees(requete?: string): Promise<EntreeApercu[]> {
  const brut = await invoke<EntreeApercuBrut[]>("lister_entrees", { requete: requete ?? null });
  return brut.map(normaliserEntree);
}

/** Révèle la valeur d'un champ secret d'une entrée (à la demande). */
export function revelerChamp(id: string, champ: string): Promise<string> {
  return invoke<string>("reveler_champ", { id, champ });
}

/** Copie un champ dans le presse-papiers, effacé après `delaiS` secondes. */
export function copierChamp(id: string, champ: string, delaiS: number): Promise<void> {
  return invoke<void>("copier_champ", { id, champ, delaiS });
}

/** Code TOTP courant d'une entrée. */
export async function obtenirTotp(id: string): Promise<CodeTotp> {
  const t = await invoke<{ code: string; secondes_restantes: number }>("obtenir_totp", { id });
  return { code: t.code, secondesRestantes: t.secondes_restantes };
}

/** Copie le code TOTP courant (effacé après `delaiS` secondes). */
export function copierTotp(id: string, delaiS: number): Promise<void> {
  return invoke<void>("copier_totp", { id, delaiS });
}

/** Données d'une entrée envoyées au backend (création/modification). */
export interface DonneesEntree {
  categorie: string;
  nom: string;
  nomUtilisateur: string | null;
  uris: string[];
  /** À la modification : vide/absent => mot de passe inchangé. */
  motDePasse: string | null;
  /** Base32 brut ou URI otpauth:// ; vide/absent => inchangé. */
  totp: string | null;
  notes: string | null;
}

/** Ajoute une entrée ; renvoie son identifiant. */
export function ajouterEntree(donnees: DonneesEntree): Promise<string> {
  return invoke<string>("ajouter_entree", { donnees });
}

/** Modifie une entrée existante. */
export function modifierEntree(id: string, donnees: DonneesEntree): Promise<void> {
  return invoke<void>("modifier_entree", { id, donnees });
}

/** Supprime une entrée. */
export function supprimerEntree(id: string): Promise<void> {
  return invoke<void>("supprimer_entree", { id });
}

/** Options de génération (mots renseigné => phrase de passe). */
export interface OptionsGenerateur {
  mots: number | null;
  longueur: number;
  minuscules: boolean;
  majuscules: boolean;
  chiffres: boolean;
  symboles: boolean;
  exclureAmbigus: boolean;
}

/** Mot de passe généré et entropie estimée. */
export interface MotDePasseGenere {
  valeur: string;
  entropieBits: number;
}

/** Génère un mot de passe ou une phrase de passe (côté cœur). */
export function genererMotDePasse(options: OptionsGenerateur): Promise<MotDePasseGenere> {
  return invoke<MotDePasseGenere>("generer_mot_de_passe", { options });
}

/** Copie un texte fourni (ex. sortie du générateur), effacé après `delaiS` s. */
export function copierTexte(valeur: string, delaiS: number): Promise<void> {
  return invoke<void>("copier_texte", { valeur, delaiS });
}

/** Entrée concernée par un constat d'audit. */
export interface ElementAudit {
  id: string;
  nom: string;
}

/** Rapport d'audit du coffre. */
export interface RapportAudit {
  faibles: ElementAudit[];
  reutilises: ElementAudit[];
  anciens: ElementAudit[];
  totalAvecMotDePasse: number;
  score: number;
}

/** Entrée dont le mot de passe figure dans une fuite connue. */
export interface ElementFuite {
  id: string;
  nom: string;
  occurrences: number;
}

/** Audit hors-ligne (réutilisés/faibles/anciens + score). */
export function lancerAudit(): Promise<RapportAudit> {
  return invoke<RapportAudit>("lancer_audit");
}

/** Vérification de fuites en ligne (k-anonymat, opt-in). */
export function verifierFuites(): Promise<ElementFuite[]> {
  return invoke<ElementFuite[]>("verifier_fuites");
}
