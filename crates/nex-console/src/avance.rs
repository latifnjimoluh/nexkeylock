//! Commandes avancées : partage chiffré, accès d'urgence et passkeys.
//!
//! L'identité de partage de l'utilisateur (clés privées hybrides) est stockée
//! dans le coffre, chiffrée comme le reste. Les bundles publics et messages
//! scellés transitent par des fichiers d'octets opaques.

use std::path::Path;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;

use nex_coffre::CoffreDeverrouille;
use nex_partage::{generer_paire, partager, recevoir, ClesPrivees, ClesPubliques, MessagePartage};
use nex_passkey::Passkey;
use nex_urgence::{recuperer_materiel, AccesUrgence};

use crate::saisie::lire_secret_entree;

/// Sous-commandes de partage chiffré de bout en bout.
#[derive(Subcommand)]
pub enum CommandeShare {
    /// Génère/charge mon identité de partage et écrit mon bundle public.
    Identity {
        /// Fichier de sortie du bundle public.
        #[arg(long)]
        sortie: PathBuf,
    },
    /// Scelle le mot de passe d'une entrée vers un destinataire.
    Send {
        /// Fichier du bundle public du destinataire.
        #[arg(long)]
        destinataire: PathBuf,
        /// Identifiant ou nom de l'entrée à partager.
        #[arg(long)]
        entree: String,
        /// Fichier de sortie du message scellé.
        #[arg(long)]
        sortie: PathBuf,
    },
    /// Ouvre un message scellé qui m'est destiné.
    Receive {
        /// Fichier du message scellé.
        #[arg(long)]
        fichier: PathBuf,
    },
}

/// Sous-commandes d'accès d'urgence.
#[derive(Subcommand)]
pub enum CommandeEmergency {
    /// Scelle un matériel d'accès (lu sur l'entrée standard) vers un contact.
    Seal {
        /// Fichier du bundle public du contact.
        #[arg(long)]
        contact: PathBuf,
        /// Délai avant accès, en jours.
        #[arg(long = "delai-jours")]
        delai_jours: u64,
        /// Fichier de sortie de l'accès scellé.
        #[arg(long)]
        sortie: PathBuf,
    },
    /// Ouvre un accès d'urgence (horloge simulée pour démonstration).
    Open {
        /// Fichier de l'accès scellé.
        #[arg(long)]
        fichier: PathBuf,
        /// Instant de la demande (Unix).
        #[arg(long)]
        depuis: u64,
        /// Instant courant simulé (Unix).
        #[arg(long)]
        maintenant: u64,
    },
}

/// Sous-commandes passkeys.
#[derive(Subcommand)]
pub enum CommandePasskey {
    /// Crée une passkey pour un site et la stocke dans le coffre.
    Create {
        /// Identifiant du site (domaine).
        rp_id: String,
    },
    /// Produit une assertion signée pour un site.
    Assert {
        /// Identifiant du site.
        rp_id: String,
        /// Défi (hexadécimal).
        #[arg(long)]
        defi: String,
        /// Origine (URL).
        #[arg(long)]
        origine: String,
    },
    /// Liste les passkeys enregistrées.
    List,
}

/// Exécute une commande `share`.
pub fn executer_share(chemin: &Path, commande: CommandeShare) -> Result<()> {
    match commande {
        CommandeShare::Identity { sortie } => share_identity(chemin, &sortie),
        CommandeShare::Send {
            destinataire,
            entree,
            sortie,
        } => share_send(chemin, &destinataire, &entree, &sortie),
        CommandeShare::Receive { fichier } => share_receive(chemin, &fichier),
    }
}

/// Exécute une commande `emergency`.
pub fn executer_emergency(chemin: &Path, commande: CommandeEmergency) -> Result<()> {
    match commande {
        CommandeEmergency::Seal {
            contact,
            delai_jours,
            sortie,
        } => emergency_seal(&contact, delai_jours, &sortie),
        CommandeEmergency::Open {
            fichier,
            depuis,
            maintenant,
        } => emergency_open(chemin, &fichier, depuis, maintenant),
    }
}

/// Exécute une commande `passkey`.
pub fn executer_passkey(chemin: &Path, commande: CommandePasskey) -> Result<()> {
    match commande {
        CommandePasskey::Create { rp_id } => passkey_create(chemin, &rp_id),
        CommandePasskey::Assert {
            rp_id,
            defi,
            origine,
        } => passkey_assert(chemin, &rp_id, &defi, &origine),
        CommandePasskey::List => passkey_list(chemin),
    }
}

// --- Identité de partage ---------------------------------------------------

/// Charge l'identité de partage du coffre, ou la crée et la persiste.
fn charger_ou_creer_identite(
    coffre: &mut CoffreDeverrouille,
) -> Result<(ClesPrivees, ClesPubliques)> {
    if let Some(octets) = coffre.identite_partage() {
        return decoder_identite(octets);
    }
    let (prive, public) = generer_paire();
    let blob = encoder_identite(&prive, &public);
    coffre.definir_identite_partage(blob);
    coffre.enregistrer()?;
    Ok((prive, public))
}

/// Encode l'identité = `u32 longueur_privée | clés privées | bundle public`.
fn encoder_identite(prive: &ClesPrivees, public: &ClesPubliques) -> Vec<u8> {
    let p = prive.vers_octets();
    let q = public.vers_octets();
    let mut v = Vec::with_capacity(4 + p.len() + q.len());
    v.extend_from_slice(&(p.len() as u32).to_le_bytes());
    v.extend_from_slice(&p);
    v.extend_from_slice(&q);
    v
}

fn decoder_identite(octets: &[u8]) -> Result<(ClesPrivees, ClesPubliques)> {
    let entete = octets
        .get(..4)
        .ok_or_else(|| anyhow!("identité de partage corrompue"))?;
    let n = u32::from_le_bytes(
        entete
            .try_into()
            .map_err(|_| anyhow!("identité de partage corrompue"))?,
    ) as usize;
    let prive = octets
        .get(4..4 + n)
        .ok_or_else(|| anyhow!("identité de partage corrompue"))?;
    let public = octets
        .get(4 + n..)
        .ok_or_else(|| anyhow!("identité de partage corrompue"))?;
    Ok((
        ClesPrivees::depuis_octets(prive)?,
        ClesPubliques::depuis_octets(public)?,
    ))
}

// --- share -----------------------------------------------------------------

fn share_identity(chemin: &Path, sortie: &Path) -> Result<()> {
    let mut coffre = crate::ouvrir_deverrouille(chemin)?;
    let (_prive, public) = charger_ou_creer_identite(&mut coffre)?;
    std::fs::write(sortie, public.vers_octets())?;
    println!("Bundle public écrit dans {}", sortie.display());
    Ok(())
}

fn share_send(chemin: &Path, destinataire: &Path, entree: &str, sortie: &Path) -> Result<()> {
    let coffre = crate::ouvrir_deverrouille(chemin)?;
    let e = crate::trouver_entree(&coffre, entree)?;
    let mdp = e
        .mot_de_passe
        .as_deref()
        .ok_or_else(|| anyhow!("l'entrée « {} » n'a pas de mot de passe", e.nom))?;
    let bundle = std::fs::read(destinataire).context("lecture du bundle destinataire")?;
    let public = ClesPubliques::depuis_octets(&bundle)?;
    let message = partager(&public, mdp.as_bytes())?;
    std::fs::write(sortie, message.vers_octets())?;
    println!(
        "Mot de passe de « {}» scellé dans {}",
        e.nom,
        sortie.display()
    );
    Ok(())
}

fn share_receive(chemin: &Path, fichier: &Path) -> Result<()> {
    let mut coffre = crate::ouvrir_deverrouille(chemin)?;
    let (prive, _public) = charger_ou_creer_identite(&mut coffre)?;
    let octets = std::fs::read(fichier)?;
    let message = MessagePartage::depuis_octets(&octets)?;
    let clair = recevoir(&prive, &message)?;
    let texte = String::from_utf8(clair).map_err(|_| anyhow!("contenu reçu non textuel"))?;
    println!("Secret reçu : {texte}");
    Ok(())
}

// --- emergency -------------------------------------------------------------

fn emergency_seal(contact: &Path, delai_jours: u64, sortie: &Path) -> Result<()> {
    let materiel = lire_secret_entree("Matériel d'accès à sceller : ")?;
    let bundle = std::fs::read(contact).context("lecture du bundle contact")?;
    let public = ClesPubliques::depuis_octets(&bundle)?;
    let acces = AccesUrgence::configurer(
        "contact",
        &public,
        materiel.as_bytes(),
        delai_jours.saturating_mul(86_400),
    )?;
    std::fs::write(sortie, acces.vers_octets())?;
    println!(
        "Accès d'urgence scellé dans {} (délai {delai_jours} jours).",
        sortie.display()
    );
    Ok(())
}

fn emergency_open(chemin: &Path, fichier: &Path, depuis: u64, maintenant: u64) -> Result<()> {
    let mut coffre = crate::ouvrir_deverrouille(chemin)?;
    let (prive, _public) = charger_ou_creer_identite(&mut coffre)?;
    let octets = std::fs::read(fichier)?;
    let mut acces = AccesUrgence::depuis_octets(&octets)?;
    acces.demander(depuis);
    match acces.liberer(maintenant) {
        Some(scelle) => {
            let materiel = recuperer_materiel(&prive, scelle)?;
            let texte = String::from_utf8(materiel).map_err(|_| anyhow!("matériel non textuel"))?;
            println!("Accès accordé. Matériel : {texte}");
            Ok(())
        }
        None => bail!("accès non disponible : le délai n'est pas encore écoulé"),
    }
}

// --- passkey ---------------------------------------------------------------

fn passkey_create(chemin: &Path, rp_id: &str) -> Result<()> {
    let mut coffre = crate::ouvrir_deverrouille(chemin)?;
    let (passkey, publique) = Passkey::creer(rp_id)?;
    coffre.ajouter_passkey(passkey.vers_octets().to_vec());
    coffre.enregistrer()?;
    println!("Passkey créée pour {rp_id}.");
    println!("Clé publique  : {}", hex::encode(publique.cle_publique));
    println!("credential_id : {}", hex::encode(&publique.credential_id));
    Ok(())
}

fn passkey_assert(chemin: &Path, rp_id: &str, defi_hex: &str, origine: &str) -> Result<()> {
    let mut coffre = crate::ouvrir_deverrouille(chemin)?;
    let mut liste: Vec<Vec<u8>> = coffre.passkeys().to_vec();
    let index = liste
        .iter()
        .position(|o| {
            Passkey::depuis_octets(o)
                .map(|p| p.rp_id() == rp_id)
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!("aucune passkey pour {rp_id}"))?;

    let mut passkey = Passkey::depuis_octets(&liste[index])?;
    let defi = hex::decode(defi_hex).map_err(|_| anyhow!("défi hexadécimal invalide"))?;
    let assertion = passkey.signer(&defi, origine);

    // Persiste le compteur incrémenté.
    liste[index] = passkey.vers_octets().to_vec();
    coffre.definir_passkeys(liste);
    coffre.enregistrer()?;

    println!(
        "authenticator_data : {}",
        hex::encode(&assertion.donnees_authentificateur)
    );
    println!("signature          : {}", hex::encode(&assertion.signature));
    println!("compteur           : {}", assertion.compteur);
    Ok(())
}

fn passkey_list(chemin: &Path) -> Result<()> {
    let coffre = crate::ouvrir_deverrouille(chemin)?;
    if coffre.passkeys().is_empty() {
        println!("(aucune passkey)");
        return Ok(());
    }
    for o in coffre.passkeys() {
        if let Ok(p) = Passkey::depuis_octets(o) {
            println!(
                "{}  (credential_id {})",
                p.rp_id(),
                hex::encode(p.credential_id())
            );
        }
    }
    Ok(())
}
