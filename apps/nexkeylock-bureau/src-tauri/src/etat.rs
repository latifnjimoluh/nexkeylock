//! État applicatif du coffre, détenu **côté backend** (jamais dans la webview).
//!
//! Le `CoffreDeverrouille` (DEK + contenu en clair) vit ici, protégé par un
//! `Mutex`. L'interface ne reçoit que des [`Apercu`] (métadonnées sans secret).

use std::path::PathBuf;
use std::sync::Mutex;

use nex_coffre::{CoffreDeverrouille, CoffreVerrouille, ParametresArgon2};
use zeroize::Zeroizing;

use crate::erreur::ErreurCommande;

/// Métadonnées non sensibles renvoyées à l'interface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Apercu {
    /// `true` si aucun coffre n'est déverrouillé en mémoire.
    pub verrouille: bool,
    /// `true` si un fichier de coffre existe sur le disque.
    pub existe: bool,
    /// Nombre d'entrées (0 si verrouillé).
    pub nombre_entrees: usize,
    /// `true` si un code de récupération est configuré.
    pub a_recuperation: bool,
}

/// État du coffre : chemin du fichier + coffre déverrouillé éventuel.
pub struct EtatCoffre {
    chemin: PathBuf,
    coffre: Option<CoffreDeverrouille>,
}

impl EtatCoffre {
    /// Construit l'état avec le chemin par défaut (interopérable avec la CLI).
    pub fn par_defaut() -> Self {
        Self::avec_chemin(chemin_par_defaut())
    }

    /// Construit l'état avec un chemin explicite (utilisé par les tests).
    pub fn avec_chemin(chemin: PathBuf) -> Self {
        Self {
            chemin,
            coffre: None,
        }
    }

    /// Indique si un fichier de coffre existe.
    pub fn coffre_existe(&self) -> bool {
        self.chemin.exists()
    }

    /// Crée un nouveau coffre et le laisse déverrouillé en mémoire.
    pub fn creer(&mut self, mot_de_passe: Zeroizing<String>) -> Result<Apercu, ErreurCommande> {
        if self.chemin.exists() {
            return Err(ErreurCommande::coffre_existant());
        }
        if let Some(parent) = self.chemin.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|_| ErreurCommande::interne("Création du dossier impossible."))?;
            }
        }
        let coffre =
            CoffreDeverrouille::creer(&self.chemin, mot_de_passe.as_bytes(), parametres_kdf())?;
        self.coffre = Some(coffre);
        Ok(self.apercu())
    }

    /// Déverrouille le coffre avec le mot de passe maître.
    pub fn deverrouiller(
        &mut self,
        mot_de_passe: Zeroizing<String>,
    ) -> Result<Apercu, ErreurCommande> {
        let verrou =
            CoffreVerrouille::ouvrir(&self.chemin).map_err(|_| ErreurCommande::introuvable())?;
        let coffre = verrou.deverrouiller(mot_de_passe.as_bytes())?;
        self.coffre = Some(coffre);
        Ok(self.apercu())
    }

    /// Verrouille le coffre : le `CoffreDeverrouille` est libéré, ce qui efface
    /// la DEK et le contenu (`ZeroizeOnDrop`).
    pub fn verrouiller(&mut self) {
        self.coffre = None;
    }

    /// Métadonnées courantes (aucun secret).
    pub fn apercu(&self) -> Apercu {
        match &self.coffre {
            Some(c) => Apercu {
                verrouille: false,
                existe: true,
                nombre_entrees: c.entrees().len(),
                a_recuperation: c.a_recuperation(),
            },
            None => Apercu {
                verrouille: true,
                existe: self.chemin.exists(),
                nombre_entrees: 0,
                a_recuperation: false,
            },
        }
    }
}

/// Conteneur partagé géré par Tauri (`State<EtatPartage>`).
pub struct EtatPartage(pub Mutex<EtatCoffre>);

impl EtatPartage {
    /// Verrouille le mutex en convertissant l'empoisonnement en erreur neutre.
    pub fn acceder(&self) -> Result<std::sync::MutexGuard<'_, EtatCoffre>, ErreurCommande> {
        self.0
            .lock()
            .map_err(|_| ErreurCommande::interne("État du coffre indisponible."))
    }
}

impl Default for EtatPartage {
    fn default() -> Self {
        EtatPartage(Mutex::new(EtatCoffre::par_defaut()))
    }
}

/// Paramètres Argon2id : allégés si `NEXKEYLOCK_KDF_RAPIDE` est défini (tests),
/// sinon production (256 Mio). Cohérent avec la CLI.
fn parametres_kdf() -> ParametresArgon2 {
    if std::env::var_os("NEXKEYLOCK_KDF_RAPIDE").is_some() {
        ParametresArgon2::new(8, 1, 1)
    } else {
        ParametresArgon2::default()
    }
}

/// Chemin par défaut du coffre : `~/.nexkeylock/coffre.vault` (même que la CLI).
fn chemin_par_defaut() -> PathBuf {
    let base = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
    match base {
        Some(racine) => PathBuf::from(racine)
            .join(".nexkeylock")
            .join("coffre.vault"),
        None => PathBuf::from("coffre.vault"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn etat_temporaire() -> (tempfile::TempDir, EtatCoffre) {
        // Garantit Argon2 rapide pour les tests.
        std::env::set_var("NEXKEYLOCK_KDF_RAPIDE", "1");
        let dossier = tempdir().unwrap();
        let chemin = dossier.path().join("coffre.vault");
        (dossier, EtatCoffre::avec_chemin(chemin))
    }

    #[test]
    fn creation_puis_apercu() {
        let (_d, mut etat) = etat_temporaire();
        assert!(!etat.coffre_existe());
        let ap = etat.creer(Zeroizing::new("maitre-correct".into())).unwrap();
        assert!(!ap.verrouille);
        assert_eq!(ap.nombre_entrees, 0);
        assert!(etat.coffre_existe());
    }

    #[test]
    fn creation_refuse_si_existant() {
        let (_d, mut etat) = etat_temporaire();
        etat.creer(Zeroizing::new("maitre".into())).unwrap();
        let e = etat.creer(Zeroizing::new("maitre".into())).unwrap_err();
        assert_eq!(e.code, "coffre_existant");
    }

    #[test]
    fn deverrouillage_correct_puis_verrouillage() {
        let (_d, mut etat) = etat_temporaire();
        etat.creer(Zeroizing::new("bon-mdp".into())).unwrap();
        etat.verrouiller();
        assert!(etat.apercu().verrouille);
        let ap = etat
            .deverrouiller(Zeroizing::new("bon-mdp".into()))
            .unwrap();
        assert!(!ap.verrouille);
        etat.verrouiller();
        assert!(etat.apercu().verrouille);
    }

    #[test]
    fn mauvais_mot_de_passe_code_neutre() {
        let (_d, mut etat) = etat_temporaire();
        etat.creer(Zeroizing::new("le-bon".into())).unwrap();
        etat.verrouiller();
        let e = etat
            .deverrouiller(Zeroizing::new("le-mauvais".into()))
            .unwrap_err();
        assert_eq!(e.code, "mot_de_passe");
        // Le message ne contient aucun des deux mots de passe.
        assert!(!e.message.contains("le-bon"));
        assert!(!e.message.contains("le-mauvais"));
    }

    #[test]
    fn deverrouiller_sans_fichier_est_introuvable() {
        let (_d, mut etat) = etat_temporaire();
        let e = etat.deverrouiller(Zeroizing::new("x".into())).unwrap_err();
        assert_eq!(e.code, "introuvable");
    }
}
