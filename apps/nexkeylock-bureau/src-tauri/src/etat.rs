//! État applicatif du coffre, détenu **côté backend** (jamais dans la webview).
//!
//! Le `CoffreDeverrouille` (DEK + contenu en clair) vit ici, protégé par un
//! `Mutex`. L'interface ne reçoit que des [`Apercu`] (métadonnées sans secret).

use std::path::PathBuf;
use std::sync::Mutex;

use nex_coffre::totp::{
    secret_base32_depuis_otpauth, secret_depuis_base32, totp, CHIFFRES_DEFAUT, PAS_DEFAUT,
};
use nex_coffre::{
    maintenant_unix, nouvel_identifiant, CoffreDeverrouille, CoffreVerrouille, Entree,
    ParametresArgon2, TypeEntree,
};
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

/// Métadonnées d'une entrée (jamais de secret : ni mot de passe ni TOTP).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntreeApercu {
    pub id: String,
    pub nom: String,
    pub nom_utilisateur: Option<String>,
    pub uris: Vec<String>,
    /// « connexion » | « note » | « secret ».
    pub categorie: String,
    pub a_mot_de_passe: bool,
    pub a_totp: bool,
}

impl EntreeApercu {
    fn depuis(e: &Entree) -> Self {
        let categorie = match e.type_entree {
            TypeEntree::Connexion => "connexion",
            TypeEntree::NoteSecurisee => "note",
            TypeEntree::SecretGenerique => "secret",
            // `TypeEntree` est `#[non_exhaustive]` : on prévoit les types futurs.
            _ => "autre",
        };
        Self {
            id: e.id.clone(),
            nom: e.nom.clone(),
            nom_utilisateur: e.nom_utilisateur.clone(),
            uris: e.uris.clone(),
            categorie: categorie.to_string(),
            a_mot_de_passe: e.mot_de_passe.is_some(),
            a_totp: e.secret_totp.is_some(),
        }
    }
}

/// Code TOTP courant et son temps de validité restant.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CodeTotp {
    pub code: String,
    pub secondes_restantes: u64,
}

/// Données d'entrée reçues de l'interface (création ou modification).
///
/// À la **modification**, `mot_de_passe`/`totp` à `None` ou vides laissent le
/// champ existant **inchangé** (on ne renvoie jamais le secret à l'interface).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DonneesEntree {
    pub categorie: String,
    pub nom: String,
    pub nom_utilisateur: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    pub mot_de_passe: Option<String>,
    /// Secret TOTP saisi : Base32 brut ou URI `otpauth://`.
    pub totp: Option<String>,
    pub notes: Option<String>,
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

    /// Configure (ou remplace) le code de récupération sur le coffre déverrouillé
    /// et renvoie le code, à afficher une seule fois.
    pub fn configurer_recuperation(&mut self) -> Result<Zeroizing<String>, ErreurCommande> {
        match &mut self.coffre {
            Some(c) => Ok(c.activer_recuperation(parametres_kdf())?),
            None => Err(ErreurCommande::verrouille()),
        }
    }

    /// Référence au coffre déverrouillé, ou erreur si verrouillé.
    fn coffre(&self) -> Result<&CoffreDeverrouille, ErreurCommande> {
        self.coffre.as_ref().ok_or_else(ErreurCommande::verrouille)
    }

    /// Liste les entrées (métadonnées), filtrées par `requete` le cas échéant.
    pub fn lister(&self, requete: Option<&str>) -> Result<Vec<EntreeApercu>, ErreurCommande> {
        let coffre = self.coffre()?;
        let entrees = match requete {
            Some(q) if !q.trim().is_empty() => coffre.rechercher(q),
            _ => coffre.entrees().iter().collect(),
        };
        Ok(entrees.into_iter().map(EntreeApercu::depuis).collect())
    }

    /// Révèle la valeur d'un champ secret d'une entrée (à la demande).
    pub fn reveler(&self, id: &str, champ: &str) -> Result<String, ErreurCommande> {
        let entree = self
            .coffre()?
            .obtenir(id)
            .ok_or_else(|| ErreurCommande::interne("Entrée introuvable."))?;
        let valeur = match champ {
            "mot_de_passe" => entree.mot_de_passe.clone(),
            "notes" => entree.notes.clone(),
            _ => return Err(ErreurCommande::interne("Champ inconnu.")),
        };
        valeur.ok_or_else(|| ErreurCommande::interne("Champ absent."))
    }

    /// Calcule le code TOTP courant d'une entrée et le temps restant.
    pub fn code_totp(&self, id: &str) -> Result<CodeTotp, ErreurCommande> {
        let entree = self
            .coffre()?
            .obtenir(id)
            .ok_or_else(|| ErreurCommande::interne("Entrée introuvable."))?;
        let secret_b32 = entree
            .secret_totp
            .as_deref()
            .ok_or_else(|| ErreurCommande::interne("Aucun secret TOTP."))?;
        let secret = secret_depuis_base32(secret_b32)
            .map_err(|_| ErreurCommande::interne("Secret TOTP invalide."))?;
        let maintenant = maintenant_unix();
        let code = totp(&secret, maintenant, PAS_DEFAUT, CHIFFRES_DEFAUT)
            .map_err(|_| ErreurCommande::interne("Calcul TOTP impossible."))?;
        Ok(CodeTotp {
            code,
            secondes_restantes: PAS_DEFAUT - (maintenant % PAS_DEFAUT),
        })
    }

    /// Ajoute une entrée et renvoie son identifiant.
    pub fn ajouter(&mut self, d: DonneesEntree) -> Result<String, ErreurCommande> {
        let totp_norm = normaliser_totp_optionnel(d.totp.as_deref())?;
        let coffre = self
            .coffre
            .as_mut()
            .ok_or_else(ErreurCommande::verrouille)?;
        let id = nouvel_identifiant().map_err(ErreurCommande::from)?;
        let mut e = Entree::connexion(&id, &d.nom, maintenant_unix());
        e.type_entree = type_depuis(&d.categorie);
        e.nom_utilisateur = non_vide(d.nom_utilisateur);
        e.uris = d.uris;
        e.mot_de_passe = non_vide(d.mot_de_passe);
        e.secret_totp = totp_norm;
        e.notes = non_vide(d.notes);
        coffre.ajouter(e);
        coffre.enregistrer()?;
        Ok(id)
    }

    /// Modifie une entrée existante. Les secrets vides/absents restent inchangés.
    pub fn modifier(&mut self, id: &str, d: DonneesEntree) -> Result<(), ErreurCommande> {
        let totp_norm = normaliser_totp_optionnel(d.totp.as_deref())?;
        let coffre = self
            .coffre
            .as_mut()
            .ok_or_else(ErreurCommande::verrouille)?;
        {
            let e = coffre
                .modifier(id)
                .ok_or_else(|| ErreurCommande::interne("Entrée introuvable."))?;
            e.type_entree = type_depuis(&d.categorie);
            e.nom = d.nom;
            e.nom_utilisateur = non_vide(d.nom_utilisateur);
            e.uris = d.uris;
            e.notes = non_vide(d.notes);
            e.maj_le = maintenant_unix();
            if let Some(mdp) = non_vide(d.mot_de_passe) {
                e.mot_de_passe = Some(mdp);
            }
            if let Some(t) = totp_norm {
                e.secret_totp = Some(t);
            }
        }
        coffre.enregistrer()?;
        Ok(())
    }

    /// Supprime une entrée par identifiant.
    pub fn supprimer(&mut self, id: &str) -> Result<(), ErreurCommande> {
        let coffre = self
            .coffre
            .as_mut()
            .ok_or_else(ErreurCommande::verrouille)?;
        if !coffre.supprimer(id) {
            return Err(ErreurCommande::interne("Entrée introuvable."));
        }
        coffre.enregistrer()?;
        Ok(())
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

/// Réduit un champ optionnel à `None` s'il est vide ou ne contient que des
/// espaces (évite de stocker des chaînes vides).
fn non_vide(valeur: Option<String>) -> Option<String> {
    valeur.filter(|s| !s.trim().is_empty())
}

/// Convertit une catégorie d'interface en [`TypeEntree`].
fn type_depuis(categorie: &str) -> TypeEntree {
    match categorie {
        "note" => TypeEntree::NoteSecurisee,
        "secret" => TypeEntree::SecretGenerique,
        _ => TypeEntree::Connexion,
    }
}

/// Normalise un secret TOTP saisi (Base32 brut ou URI `otpauth://`) en Base32,
/// ou `None` si rien n'est fourni.
fn normaliser_totp_optionnel(saisie: Option<&str>) -> Result<Option<String>, ErreurCommande> {
    let Some(s) = saisie.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let base32 = if s.starts_with("otpauth://") {
        secret_base32_depuis_otpauth(s)
            .map_err(|_| ErreurCommande::interne("Secret TOTP (otpauth) invalide."))?
    } else {
        secret_depuis_base32(s)
            .map_err(|_| ErreurCommande::interne("Secret TOTP Base32 invalide."))?;
        s.to_string()
    };
    Ok(Some(base32))
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

    fn donnees(nom: &str) -> DonneesEntree {
        DonneesEntree {
            categorie: "connexion".into(),
            nom: nom.into(),
            nom_utilisateur: Some("moi@exemple.fr".into()),
            uris: vec!["https://exemple.fr".into()],
            mot_de_passe: Some("s3cr3t".into()),
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            notes: None,
        }
    }

    #[test]
    fn lister_rechercher_reveler_et_totp() {
        let (_d, mut etat) = etat_temporaire();
        etat.creer(Zeroizing::new("maitre".into())).unwrap();
        let id = etat.ajouter(donnees("Banque")).unwrap();

        let liste = etat.lister(None).unwrap();
        assert_eq!(liste.len(), 1);
        assert_eq!(liste[0].nom, "Banque");
        assert_eq!(liste[0].categorie, "connexion");
        assert!(liste[0].a_mot_de_passe && liste[0].a_totp);

        assert_eq!(etat.lister(Some("banq")).unwrap().len(), 1);
        assert_eq!(etat.lister(Some("introuvable")).unwrap().len(), 0);

        assert_eq!(etat.reveler(&id, "mot_de_passe").unwrap(), "s3cr3t");
        assert!(etat.reveler(&id, "champ-inconnu").is_err());

        let t = etat.code_totp(&id).unwrap();
        assert_eq!(t.code.len(), 6);
        assert!(t.secondes_restantes >= 1 && t.secondes_restantes <= 30);
    }

    #[test]
    fn ajout_modification_suppression() {
        let (_d, mut etat) = etat_temporaire();
        etat.creer(Zeroizing::new("maitre".into())).unwrap();
        let id = etat.ajouter(donnees("Banque")).unwrap();

        // Modification : nouveau nom, mot de passe vide => inchangé.
        let mut maj = donnees("Banque renommée");
        maj.mot_de_passe = None;
        etat.modifier(&id, maj).unwrap();
        let liste = etat.lister(None).unwrap();
        assert_eq!(liste[0].nom, "Banque renommée");
        assert_eq!(etat.reveler(&id, "mot_de_passe").unwrap(), "s3cr3t");

        // Suppression.
        etat.supprimer(&id).unwrap();
        assert_eq!(etat.lister(None).unwrap().len(), 0);
        assert!(etat.supprimer(&id).is_err());
    }

    #[test]
    fn totp_otpauth_normalise() {
        let (_d, mut etat) = etat_temporaire();
        etat.creer(Zeroizing::new("maitre".into())).unwrap();
        let mut d = donnees("Compte");
        d.totp = Some("otpauth://totp/Compte?secret=JBSWY3DPEHPK3PXP&issuer=X".into());
        let id = etat.ajouter(d).unwrap();
        // Le code TOTP se calcule => le secret a bien été normalisé et stocké.
        assert_eq!(etat.code_totp(&id).unwrap().code.len(), 6);
    }

    #[test]
    fn lister_refuse_si_verrouille() {
        let (_d, etat) = etat_temporaire();
        assert_eq!(etat.lister(None).unwrap_err().code, "verrouille");
    }

    #[test]
    fn recuperation_exige_un_coffre_deverrouille() {
        let (_d, mut etat) = etat_temporaire();
        // Verrouillé : refus.
        let e = etat.configurer_recuperation().unwrap_err();
        assert_eq!(e.code, "verrouille");
        // Déverrouillé : un code est produit et la récupération est active.
        etat.creer(Zeroizing::new("maitre".into())).unwrap();
        let code = etat.configurer_recuperation().unwrap();
        assert!(!code.is_empty());
        assert!(etat.apercu().a_recuperation);
    }
}
