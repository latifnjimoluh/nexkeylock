//! Commandes CLI de mise à jour et de paramètres — le « volet paramètres ».
//!
//! - `nexkeylock parametres`  : affiche/modifie les préférences (vérif. auto…).
//! - `nexkeylock maj`         : vérifie, télécharge ou installe la dernière version.
//! - Vérification automatique au lancement des autres commandes (best-effort),
//!   avec bandeau et notification système quand une mise à jour est disponible.
//!
//! Toute la logique réseau/semver vit dans le crate `nex-maj` ; ce module ne fait
//! que l'orchestration CLI et l'affichage.

use anyhow::{anyhow, bail, Result};
use clap::{Args, ValueEnum};
use nex_coffre::maintenant_unix;
use nex_maj::{Config, EtatMaj};

/// Version installée (celle de ce binaire).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version courante effective. Normalement celle du binaire, mais surchargée par
/// `NEXKEYLOCK_VERSION_ACTUELLE` si définie — utile pour le diagnostic et pour
/// forcer une re-détection (ex. vérifier le flux de mise à jour).
fn version_actuelle() -> String {
    std::env::var("NEXKEYLOCK_VERSION_ACTUELLE").unwrap_or_else(|_| VERSION.to_string())
}

/// Bascule on/off pour les options booléennes des paramètres.
#[derive(Clone, Copy, ValueEnum)]
pub enum Bascule {
    On,
    Off,
}

/// Arguments de `nexkeylock parametres`.
#[derive(Args)]
pub struct CommandeParametres {
    /// Active (on) ou désactive (off) la vérification automatique des mises à jour.
    #[arg(long = "maj-auto", value_enum)]
    maj_auto: Option<Bascule>,
    /// Intervalle minimal entre deux vérifications automatiques, en heures.
    #[arg(long)]
    intervalle: Option<u64>,
}

/// Arguments de `nexkeylock maj`.
#[derive(Args)]
pub struct CommandeMaj {
    /// Vérifier la disponibilité d'une mise à jour (action par défaut).
    #[arg(long)]
    verifier: bool,
    /// Télécharger l'installateur de la dernière version (sans le lancer).
    #[arg(long)]
    telecharger: bool,
    /// Télécharger puis lancer l'installateur de la dernière version.
    #[arg(long)]
    installer: bool,
}

/// Indique si la vérification automatique est désactivée par l'environnement
/// (mode test/CI : on n'effectue aucun appel réseau pendant les tests).
fn verif_desactivee_par_env() -> bool {
    std::env::var_os("NEXKEYLOCK_SANS_VERIF_MAJ").is_some()
        || std::env::var_os("NEXKEYLOCK_KDF_RAPIDE").is_some()
}

/// Affiche le volet paramètres et applique d'éventuelles modifications.
pub fn executer_parametres(cmd: CommandeParametres) -> Result<()> {
    let mut config = Config::charger()?;
    let mut modifie = false;
    if let Some(b) = cmd.maj_auto {
        config.verification_auto = matches!(b, Bascule::On);
        modifie = true;
    }
    if let Some(h) = cmd.intervalle {
        if h == 0 {
            bail!("l'intervalle doit être d'au moins 1 heure");
        }
        config.intervalle_heures = h;
        modifie = true;
    }
    if modifie {
        config.enregistrer()?;
        println!("Paramètres enregistrés.\n");
    }
    afficher_parametres(&config)?;
    Ok(())
}

/// Affiche l'état courant des paramètres.
fn afficher_parametres(config: &Config) -> Result<()> {
    let etat = if config.verification_auto {
        "ACTIVÉE"
    } else {
        "DÉSACTIVÉE"
    };
    println!("Paramètres nexkeylock");
    println!("  Vérification automatique des mises à jour : {etat}");
    println!(
        "  Intervalle de vérification                : {} h",
        config.intervalle_heures
    );
    println!(
        "  Dernière vérification                     : {}",
        delai_humain(config.derniere_verification_unix)
    );
    println!(
        "  Version installée                         : {}",
        version_actuelle()
    );
    if let Some(v) = &config.derniere_version_connue {
        println!("  Dernière version connue sur le dépôt      : {v}");
    }
    println!(
        "  Fichier de configuration                  : {}",
        Config::chemin()?.display()
    );
    Ok(())
}

/// Exécute `nexkeylock maj` : vérifie et, au besoin, télécharge/installe.
pub fn executer_maj(cmd: CommandeMaj) -> Result<()> {
    let mut config = Config::charger().unwrap_or_default();
    let version = version_actuelle();
    println!("Vérification des mises à jour…");
    let etat = nex_maj::verifier(&version, nex_maj::TIMEOUT_VERIF)?;
    config.derniere_verification_unix = maintenant_unix();

    match etat {
        EtatMaj::AJour { version } => {
            config.derniere_version_connue = Some(version.clone());
            let _ = config.enregistrer();
            println!("✓ nexkeylock est à jour (version {version}).");
            Ok(())
        }
        EtatMaj::Disponible {
            version_actuelle,
            release,
        } => {
            config.derniere_version_connue = Some(release.version.clone());
            let _ = config.enregistrer();
            println!(
                "⚠ Nouvelle version disponible : {} (installée : {version_actuelle})",
                release.etiquette
            );
            println!("  Page de la version : {}", release.url_page);
            nex_maj::notifier(
                "nexkeylock — mise à jour disponible",
                &format!(
                    "La version {} est disponible (vous avez {version_actuelle}).",
                    release.version
                ),
            );

            if cmd.installer || cmd.telecharger {
                let asset = release.installateur().ok_or_else(|| {
                    anyhow!(
                        "aucun installateur attaché à cette version ; voir {}",
                        release.url_page
                    )
                })?;
                let dossier = dossier_telechargements();
                println!("  Téléchargement de {} …", asset.name);
                let fichier =
                    nex_maj::telecharger(asset, &dossier, nex_maj::TIMEOUT_TELECHARGEMENT)?;
                println!("  Enregistré : {}", fichier.display());
                if cmd.installer {
                    println!("  Lancement de l'installateur…");
                    lancer(&fichier)?;
                }
            } else {
                println!("  Pour installer : nexkeylock maj --installer");
            }
            Ok(())
        }
    }
}

/// Vérification automatique au lancement (best-effort) : ne bloque jamais et ne
/// fait jamais échouer la commande en cours. Émet un bandeau sur stderr et une
/// notification système quand une nouvelle version est détectée.
pub fn verifier_au_lancement() {
    if verif_desactivee_par_env() {
        return;
    }
    let mut config = match Config::charger() {
        Ok(c) => c,
        Err(_) => return,
    };
    if !nex_maj::verification_due(&config, maintenant_unix()) {
        return;
    }
    // On avance l'horodatage AVANT l'appel réseau : en cas d'échec (hors-ligne),
    // on ne réessaie pas à chaque commande.
    config.derniere_verification_unix = maintenant_unix();
    let version = version_actuelle();

    match nex_maj::verifier(&version, nex_maj::TIMEOUT_AUTO) {
        Ok(EtatMaj::Disponible { release, .. }) => {
            let deja_notifiee =
                config.derniere_version_connue.as_deref() == Some(release.version.as_str());
            config.derniere_version_connue = Some(release.version.clone());
            let _ = config.enregistrer();
            eprintln!(
                "⚠ nexkeylock {} est disponible (vous avez {version}). \
                 Mettez à jour avec : nexkeylock maj --installer",
                release.etiquette
            );
            if !deja_notifiee {
                nex_maj::notifier(
                    "nexkeylock — mise à jour disponible",
                    &format!("La version {} est disponible.", release.version),
                );
            }
        }
        Ok(EtatMaj::AJour { version }) => {
            config.derniere_version_connue = Some(version);
            let _ = config.enregistrer();
        }
        Err(_) => {
            // Hors-ligne ou API indisponible : silencieux. L'horodatage avancé
            // est tout de même enregistré pour espacer les tentatives.
            let _ = config.enregistrer();
        }
    }
}

/// Met en forme un délai écoulé depuis un horodatage Unix.
fn delai_humain(horodatage: u64) -> String {
    if horodatage == 0 {
        return "jamais".to_string();
    }
    let delta = maintenant_unix().saturating_sub(horodatage);
    if delta < 60 {
        format!("il y a {delta} s")
    } else if delta < 3_600 {
        format!("il y a {} min", delta / 60)
    } else if delta < 86_400 {
        format!("il y a {} h", delta / 3_600)
    } else {
        format!("il y a {} j", delta / 86_400)
    }
}

/// Dossier de téléchargement (Téléchargements de l'utilisateur, sinon temp).
fn dossier_telechargements() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os("USERPROFILE") {
        let d = std::path::PathBuf::from(p).join("Downloads");
        if d.is_dir() {
            return d;
        }
    }
    std::env::temp_dir()
}

/// Lance un exécutable (l'installateur déclenche son élévation UAC lui-même).
fn lancer(chemin: &std::path::Path) -> Result<()> {
    std::process::Command::new(chemin)
        .spawn()
        .map_err(|e| anyhow!("impossible de lancer l'installateur : {e}"))?;
    Ok(())
}
