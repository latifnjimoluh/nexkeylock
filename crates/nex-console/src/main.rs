//! Interface en ligne de commande de nexkeylock.
//!
//! Commandes : `init`, `unlock`, `add`, `get`, `list`, `edit`, `rm`,
//! `generate`, `audit`, `totp`, `export`, `import`, `change-password`.
//!
//! Le mot de passe maître se fournit via la variable `NEXKEYLOCK_MDP`
//! (automatisation), une saisie masquée au terminal, ou l'entrée standard.
//! Le chemin du coffre : option `--coffre`, variable `NEXKEYLOCK_COFFRE`, ou
//! `~/.nexkeylock/coffre.vault` par défaut.

mod avance;
mod durcissement;
mod maj;
mod presse_papiers;
mod saisie;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use nex_coffre::audit::auditer;
use nex_coffre::generateur::{
    entropie_bits, entropie_phrase, generer_mot_de_passe, generer_phrase, OptionsMotDePasse,
};
use nex_coffre::totp::{secret_depuis_base32, totp, CHIFFRES_DEFAUT, PAS_DEFAUT};
use nex_coffre::{
    maintenant_unix, nouvel_identifiant, CoffreDeverrouille, CoffreVerrouille, Entree,
    ParametresArgon2,
};

use crate::avance::{CommandeEmergency, CommandePasskey, CommandeShare};
use crate::maj::{CommandeMaj, CommandeParametres};
use crate::saisie::{
    lire_code_recuperation, lire_mot_de_passe, lire_nouveau_mot_de_passe, lire_secret_entree,
};

/// Délai d'effacement du presse-papiers, en secondes.
const DELAI_PRESSE_PAPIERS: u64 = 15;

#[derive(Parser)]
#[command(
    name = "nexkeylock",
    version,
    about = "Gestionnaire de mots de passe à architecture zéro-connaissance"
)]
struct Cli {
    /// Chemin du fichier de coffre.
    #[arg(long, global = true)]
    coffre: Option<PathBuf>,
    #[command(subcommand)]
    commande: Commande,
}

#[derive(Subcommand)]
enum Commande {
    /// Crée un nouveau coffre.
    Init,
    /// Vérifie le mot de passe maître et affiche le nombre d'entrées.
    Unlock,
    /// Ajoute une entrée.
    Add(ArgsAdd),
    /// Affiche une entrée (et révèle son mot de passe).
    Get {
        /// Identifiant exact ou terme de recherche.
        requete: String,
        /// Copier le mot de passe dans le presse-papiers au lieu de l'afficher.
        #[arg(long)]
        copier: bool,
    },
    /// Liste les entrées (sans les mots de passe).
    List,
    /// Modifie une entrée.
    Edit(ArgsEdit),
    /// Supprime une entrée.
    Rm {
        /// Identifiant de l'entrée.
        id: String,
    },
    /// Génère un mot de passe ou une phrase de passe (sans coffre).
    Generate(ArgsGenerate),
    /// Audit hors-ligne du coffre.
    Audit,
    /// Calcule le code TOTP courant d'une entrée.
    Totp {
        /// Identifiant de l'entrée.
        id: String,
    },
    /// Exporte le coffre vers un fichier (chiffré par défaut).
    Export {
        /// Fichier de destination.
        fichier: PathBuf,
        /// Exporter le contenu EN CLAIR (non chiffré) pour migration.
        #[arg(long)]
        en_clair: bool,
        /// Confirmation explicite requise pour un export en clair.
        #[arg(long = "je-confirme-le-risque")]
        confirme: bool,
    },
    /// Importe un coffre chiffré depuis un fichier.
    Import {
        /// Fichier source.
        fichier: PathBuf,
        /// Écraser un coffre existant.
        #[arg(long)]
        force: bool,
    },
    /// Change le mot de passe maître (réemballe la DEK).
    ChangePassword,
    /// Configure un code de récupération (affiché une seule fois).
    RecoverySetup,
    /// Restaure l'accès via le code de récupération et définit un nouveau mot
    /// de passe maître.
    RecoveryReset,
    /// Partage chiffré de bout en bout (hybride post-quantique).
    Share {
        #[command(subcommand)]
        commande: CommandeShare,
    },
    /// Accès d'urgence pour un contact de confiance.
    Emergency {
        #[command(subcommand)]
        commande: CommandeEmergency,
    },
    /// Passkeys (WebAuthn).
    Passkey {
        #[command(subcommand)]
        commande: CommandePasskey,
    },
    /// Affiche ou modifie les paramètres (mises à jour automatiques…).
    Parametres(CommandeParametres),
    /// Vérifie, télécharge ou installe la dernière version.
    Maj(CommandeMaj),
}

#[derive(Args)]
struct ArgsAdd {
    /// Nom de l'entrée.
    nom: String,
    /// Nom d'utilisateur.
    #[arg(long)]
    utilisateur: Option<String>,
    /// URI (répétable).
    #[arg(long = "uri")]
    uris: Vec<String>,
    /// Notes.
    #[arg(long)]
    notes: Option<String>,
    /// Secret TOTP (Base32).
    #[arg(long)]
    totp: Option<String>,
    /// Générer un mot de passe au lieu de le saisir.
    #[arg(long)]
    generer: bool,
    /// Longueur du mot de passe généré.
    #[arg(long, default_value_t = 20)]
    longueur: usize,
}

#[derive(Args)]
struct ArgsEdit {
    /// Identifiant de l'entrée.
    id: String,
    /// Nouveau nom.
    #[arg(long)]
    nom: Option<String>,
    /// Nouveau nom d'utilisateur.
    #[arg(long)]
    utilisateur: Option<String>,
    /// Nouvelles notes.
    #[arg(long)]
    notes: Option<String>,
    /// Redemander le mot de passe de l'entrée.
    #[arg(long = "mot-de-passe")]
    mot_de_passe: bool,
}

#[derive(Args)]
struct ArgsGenerate {
    /// Longueur du mot de passe.
    #[arg(long, default_value_t = 20)]
    longueur: usize,
    /// Générer une phrase de passe de N mots (diceware).
    #[arg(long)]
    mots: Option<usize>,
    /// Exclure les symboles.
    #[arg(long)]
    sans_symboles: bool,
    /// Copier dans le presse-papiers au lieu d'afficher.
    #[arg(long)]
    copier: bool,
}

fn main() -> ExitCode {
    // Durcissement du processus dès le démarrage, avant toute manipulation de
    // secret (désactivation des core dumps ; le verrouillage des pages de clés
    // est porté par les types secrets de nex-cryptographie).
    durcissement::desactiver_core_dumps();

    let cli = Cli::parse();
    match executer(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(erreur) => {
            // Le message d'erreur ne contient jamais de secret.
            eprintln!("Erreur : {erreur:#}");
            ExitCode::FAILURE
        }
    }
}

fn executer(cli: Cli) -> Result<()> {
    // Vérification automatique des mises à jour (best-effort, ~1×/jour), sauf
    // pour les commandes de mise à jour/paramètres qui s'en chargent elles-mêmes.
    if !matches!(cli.commande, Commande::Maj(_) | Commande::Parametres(_)) {
        maj::verifier_au_lancement();
    }
    let chemin = chemin_coffre(cli.coffre);
    match cli.commande {
        Commande::Init => cmd_init(&chemin),
        Commande::Unlock => cmd_unlock(&chemin),
        Commande::Add(args) => cmd_add(&chemin, args),
        Commande::Get { requete, copier } => cmd_get(&chemin, &requete, copier),
        Commande::List => cmd_list(&chemin),
        Commande::Edit(args) => cmd_edit(&chemin, args),
        Commande::Rm { id } => cmd_rm(&chemin, &id),
        Commande::Generate(args) => cmd_generate(args),
        Commande::Audit => cmd_audit(&chemin),
        Commande::Totp { id } => cmd_totp(&chemin, &id),
        Commande::Export {
            fichier,
            en_clair,
            confirme,
        } => cmd_export(&chemin, &fichier, en_clair, confirme),
        Commande::Import { fichier, force } => cmd_import(&chemin, &fichier, force),
        Commande::ChangePassword => cmd_change_password(&chemin),
        Commande::RecoverySetup => cmd_recovery_setup(&chemin),
        Commande::RecoveryReset => cmd_recovery_reset(&chemin),
        Commande::Share { commande } => avance::executer_share(&chemin, commande),
        Commande::Emergency { commande } => avance::executer_emergency(&chemin, commande),
        Commande::Passkey { commande } => avance::executer_passkey(&chemin, commande),
        Commande::Parametres(cmd) => maj::executer_parametres(cmd),
        Commande::Maj(cmd) => maj::executer_maj(cmd),
    }
}

/// Résout le chemin du coffre : option, variable d'environnement, ou défaut.
fn chemin_coffre(option: Option<PathBuf>) -> PathBuf {
    if let Some(p) = option {
        return p;
    }
    if let Some(p) = std::env::var_os("NEXKEYLOCK_COFFRE") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
    match base {
        Some(racine) => PathBuf::from(racine)
            .join(".nexkeylock")
            .join("coffre.vault"),
        None => PathBuf::from("coffre.vault"),
    }
}

/// Paramètres Argon2id : légers si `NEXKEYLOCK_KDF_RAPIDE` est défini (tests),
/// sinon valeurs de production (256 Mio).
fn parametres_kdf() -> ParametresArgon2 {
    if std::env::var_os("NEXKEYLOCK_KDF_RAPIDE").is_some() {
        ParametresArgon2::new(8, 1, 1)
    } else {
        ParametresArgon2::default()
    }
}

/// Ouvre et déverrouille le coffre (demande le mot de passe maître).
fn ouvrir_deverrouille(chemin: &Path) -> Result<CoffreDeverrouille> {
    let verrou = CoffreVerrouille::ouvrir(chemin)
        .with_context(|| format!("ouverture du coffre « {} »", chemin.display()))?;
    let mdp = lire_mot_de_passe("Mot de passe maître : ")?;
    let coffre = verrou.deverrouiller(mdp.as_bytes())?;
    Ok(coffre)
}

fn cmd_init(chemin: &Path) -> Result<()> {
    if chemin.exists() {
        bail!(
            "un coffre existe déjà à « {} » ; refus de l'écraser",
            chemin.display()
        );
    }
    creer_repertoire_parent(chemin)?;
    let mdp = lire_nouveau_mot_de_passe()?;
    CoffreDeverrouille::creer(chemin, mdp.as_bytes(), parametres_kdf())?;
    println!("Coffre créé : {}", chemin.display());
    println!(
        "Conservez précieusement votre mot de passe maître : il est IMPOSSIBLE de le récupérer."
    );
    Ok(())
}

fn cmd_unlock(chemin: &Path) -> Result<()> {
    let coffre = ouvrir_deverrouille(chemin)?;
    println!(
        "Coffre déverrouillé : {} entrée(s).",
        coffre.entrees().len()
    );
    Ok(())
}

fn cmd_add(chemin: &Path, args: ArgsAdd) -> Result<()> {
    let mut coffre = ouvrir_deverrouille(chemin)?;
    let id = nouvel_identifiant()?;
    let mut entree = Entree::connexion(&id, &args.nom, maintenant_unix());
    entree.nom_utilisateur = args.utilisateur;
    entree.uris = args.uris;
    entree.notes = args.notes;
    entree.secret_totp = args.totp;

    let secret: Zeroizing<String> = if args.generer {
        let options = OptionsMotDePasse {
            longueur: args.longueur,
            ..OptionsMotDePasse::default()
        };
        let genere = generer_mot_de_passe(&options)?;
        println!(
            "Mot de passe généré ({:.0} bits d'entropie estimée).",
            entropie_bits(options.jeu().len(), options.longueur)
        );
        genere
    } else {
        lire_secret_entree("Mot de passe de l'entrée : ")?
    };
    entree.mot_de_passe = Some(secret.to_string());

    coffre.ajouter(entree);
    coffre.enregistrer()?;
    println!("Entrée ajoutée : {id}");
    Ok(())
}

fn cmd_get(chemin: &Path, requete: &str, copier: bool) -> Result<()> {
    let coffre = ouvrir_deverrouille(chemin)?;
    let entree = trouver_entree(&coffre, requete)?;
    afficher_entree(entree);
    if let Some(mdp) = &entree.mot_de_passe {
        if copier {
            copier_secret(mdp)?;
        } else {
            println!("Mot de passe : {mdp}");
        }
    }
    Ok(())
}

fn cmd_list(chemin: &Path) -> Result<()> {
    let coffre = ouvrir_deverrouille(chemin)?;
    if coffre.entrees().is_empty() {
        println!("(coffre vide)");
        return Ok(());
    }
    for entree in coffre.entrees() {
        let utilisateur = entree.nom_utilisateur.as_deref().unwrap_or("-");
        println!("{}  {}  ({utilisateur})", entree.id, entree.nom);
    }
    Ok(())
}

fn cmd_edit(chemin: &Path, args: ArgsEdit) -> Result<()> {
    let mut coffre = ouvrir_deverrouille(chemin)?;
    {
        let entree = coffre
            .modifier(&args.id)
            .ok_or_else(|| anyhow!("entrée introuvable : {}", args.id))?;
        if let Some(nom) = args.nom {
            entree.nom = nom;
        }
        if args.utilisateur.is_some() {
            entree.nom_utilisateur = args.utilisateur;
        }
        if args.notes.is_some() {
            entree.notes = args.notes;
        }
        entree.maj_le = maintenant_unix();
    }
    if args.mot_de_passe {
        let secret = lire_secret_entree("Nouveau mot de passe de l'entrée : ")?;
        coffre
            .modifier(&args.id)
            .ok_or_else(|| anyhow!("entrée introuvable : {}", args.id))?
            .mot_de_passe = Some(secret.to_string());
    }
    coffre.enregistrer()?;
    println!("Entrée modifiée : {}", args.id);
    Ok(())
}

fn cmd_rm(chemin: &Path, id: &str) -> Result<()> {
    let mut coffre = ouvrir_deverrouille(chemin)?;
    if !coffre.supprimer(id) {
        bail!("entrée introuvable : {id}");
    }
    coffre.enregistrer()?;
    println!("Entrée supprimée : {id}");
    Ok(())
}

fn cmd_generate(args: ArgsGenerate) -> Result<()> {
    if let Some(nb_mots) = args.mots {
        let phrase = generer_phrase(nb_mots, '-')?;
        if args.copier {
            copier_secret(&phrase)?;
        } else {
            println!("{}", phrase.as_str());
        }
        eprintln!("Entropie estimée : {:.1} bits.", entropie_phrase(nb_mots));
    } else {
        let options = OptionsMotDePasse {
            longueur: args.longueur,
            symboles: !args.sans_symboles,
            ..OptionsMotDePasse::default()
        };
        let mdp = generer_mot_de_passe(&options)?;
        if args.copier {
            copier_secret(&mdp)?;
        } else {
            println!("{}", mdp.as_str());
        }
        eprintln!(
            "Entropie estimée : {:.1} bits.",
            entropie_bits(options.jeu().len(), options.longueur)
        );
    }
    Ok(())
}

fn cmd_audit(chemin: &Path) -> Result<()> {
    let coffre = ouvrir_deverrouille(chemin)?;
    let rapport = auditer(coffre.contenu(), maintenant_unix(), 365 * 86_400, 60.0);
    println!("Mots de passe faibles    : {}", rapport.faibles.len());
    println!("Mots de passe réutilisés : {}", rapport.reutilises.len());
    println!("Entrées anciennes (>1 an): {}", rapport.anciens.len());
    for id in &rapport.faibles {
        println!("  faible    : {id}");
    }
    for id in &rapport.reutilises {
        println!("  réutilisé : {id}");
    }
    Ok(())
}

fn cmd_totp(chemin: &Path, id: &str) -> Result<()> {
    let coffre = ouvrir_deverrouille(chemin)?;
    let entree = trouver_entree(&coffre, id)?;
    let secret_b32 = entree
        .secret_totp
        .as_deref()
        .ok_or_else(|| anyhow!("aucun secret TOTP pour cette entrée"))?;
    let secret = secret_depuis_base32(secret_b32)?;
    let maintenant = maintenant_unix();
    let code = totp(&secret, maintenant, PAS_DEFAUT, CHIFFRES_DEFAUT)?;
    let restant = PAS_DEFAUT - (maintenant % PAS_DEFAUT);
    println!("{code}  (valide encore {restant}s)");
    Ok(())
}

fn cmd_export(chemin: &Path, fichier: &Path, en_clair: bool, confirme: bool) -> Result<()> {
    if en_clair {
        if !confirme {
            bail!(
                "export en clair refusé : ajoutez --je-confirme-le-risque \
                 (le fichier ne sera PAS chiffré)"
            );
        }
        let coffre = ouvrir_deverrouille(chemin)?;
        let mut octets = Zeroizing::new(Vec::new());
        ciborium::into_writer(coffre.contenu(), &mut *octets)
            .map_err(|_| anyhow!("échec de la sérialisation du contenu"))?;
        std::fs::write(fichier, octets.as_slice())?;
        eprintln!("ATTENTION : export EN CLAIR (non chiffré). Détruisez ce fichier après usage.");
        println!("Contenu exporté en clair vers {}", fichier.display());
    } else {
        // Le blob est déjà chiffré : on valide puis on copie.
        CoffreVerrouille::ouvrir(chemin)?;
        std::fs::copy(chemin, fichier)?;
        println!("Coffre (chiffré) exporté vers {}", fichier.display());
    }
    Ok(())
}

fn cmd_import(chemin: &Path, fichier: &Path, force: bool) -> Result<()> {
    // Valide le fichier importé (format + en-tête) avant de l'installer.
    CoffreVerrouille::ouvrir(fichier).context("fichier importé invalide")?;
    if chemin.exists() && !force {
        bail!(
            "un coffre existe déjà à « {} » ; utilisez --force pour l'écraser",
            chemin.display()
        );
    }
    creer_repertoire_parent(chemin)?;
    std::fs::copy(fichier, chemin)?;
    println!("Coffre importé vers {}", chemin.display());
    Ok(())
}

fn cmd_change_password(chemin: &Path) -> Result<()> {
    let mut coffre = ouvrir_deverrouille(chemin)?;
    let nouveau = lire_nouveau_mot_de_passe()?;
    coffre.changer_mot_de_passe(nouveau.as_bytes())?;
    println!("Mot de passe maître changé.");
    Ok(())
}

fn cmd_recovery_setup(chemin: &Path) -> Result<()> {
    let mut coffre = ouvrir_deverrouille(chemin)?;
    let code = coffre.activer_recuperation(parametres_kdf())?;
    println!("Code de récupération (à conserver hors ligne, affiché une seule fois) :");
    println!("  {}", code.as_str());
    println!("Sans ce code NI votre mot de passe maître, le coffre est irrécupérable.");
    Ok(())
}

fn cmd_recovery_reset(chemin: &Path) -> Result<()> {
    let verrou = CoffreVerrouille::ouvrir(chemin)
        .with_context(|| format!("ouverture du coffre « {} »", chemin.display()))?;
    let code = lire_code_recuperation()?;
    let mut coffre = verrou.deverrouiller_par_recuperation(&code)?;
    let nouveau = lire_nouveau_mot_de_passe()?;
    coffre.changer_mot_de_passe(nouveau.as_bytes())?;
    println!("Accès restauré et nouveau mot de passe maître défini.");
    Ok(())
}

/// Trouve une entrée par identifiant exact, sinon par recherche.
fn trouver_entree<'a>(coffre: &'a CoffreDeverrouille, requete: &str) -> Result<&'a Entree> {
    if let Some(entree) = coffre.obtenir(requete) {
        return Ok(entree);
    }
    let resultats = coffre.rechercher(requete);
    match resultats.len() {
        0 => bail!("aucune entrée ne correspond à « {requete} »"),
        1 => Ok(resultats[0]),
        n => {
            for entree in &resultats {
                eprintln!("  {}  {}", entree.id, entree.nom);
            }
            bail!("{n} entrées correspondent ; précisez l'identifiant")
        }
    }
}

/// Affiche les champs non secrets d'une entrée.
fn afficher_entree(entree: &Entree) {
    println!("Identifiant : {}", entree.id);
    println!("Nom         : {}", entree.nom);
    if let Some(u) = &entree.nom_utilisateur {
        println!("Utilisateur : {u}");
    }
    for uri in &entree.uris {
        println!("URI         : {uri}");
    }
    if let Some(n) = &entree.notes {
        println!("Notes       : {n}");
    }
}

/// Crée le répertoire parent du chemin s'il n'existe pas.
fn creer_repertoire_parent(chemin: &Path) -> Result<()> {
    if let Some(parent) = chemin.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Copie un secret dans le presse-papiers puis l'efface après un délai.
#[cfg(feature = "presse-papiers")]
fn copier_secret(valeur: &str) -> Result<()> {
    use crate::presse_papiers::{copier_temporaire, PressePapiersSysteme};
    use std::time::Duration;

    let mut pp = PressePapiersSysteme::nouveau()?;
    println!("Copié dans le presse-papiers (effacement dans {DELAI_PRESSE_PAPIERS}s)…");
    copier_temporaire(&mut pp, valeur, Duration::from_secs(DELAI_PRESSE_PAPIERS))?;
    println!("Presse-papiers effacé.");
    Ok(())
}

/// Variante sans support presse-papiers compilé.
#[cfg(not(feature = "presse-papiers"))]
fn copier_secret(_valeur: &str) -> Result<()> {
    let _ = DELAI_PRESSE_PAPIERS;
    bail!("support du presse-papiers non compilé (recompiler avec --features presse-papiers)")
}
