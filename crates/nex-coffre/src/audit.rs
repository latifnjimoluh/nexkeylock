//! Audit de sécurité **local** du coffre et surveillance des fuites par
//! **k-anonymat**.
//!
//! Toutes les analyses hors-ligne (mots de passe faibles, réutilisés, anciens)
//! restent sur l'appareil. La vérification de fuites n'envoie **jamais** le mot
//! de passe ni son condensat complet : seul un **préfixe de 5 caractères** du
//! SHA-1 transite, derrière un [`FournisseurFuites`] abstrait et *mockable*.

use std::collections::HashMap;

use sha1::{Digest, Sha1};

use crate::erreurs::ErreurCoffre;
use crate::modele::ContenuCoffre;

/// Source de données de fuites interrogée par préfixe (k-anonymat).
///
/// L'implémentation réelle (client HTTP type *Have I Been Pwned*) vit en dehors
/// du cœur ; les tests fournissent une implémentation simulée, sans réseau.
pub trait FournisseurFuites {
    /// Renvoie les couples `(suffixe_hex_majuscule, occurrences)` pour un
    /// `prefixe` de 5 caractères hexadécimaux majuscules.
    ///
    /// # Erreurs
    /// [`ErreurCoffre::Fuites`] si la source est indisponible.
    fn suffixes(&self, prefixe: &str) -> Result<Vec<(String, u64)>, ErreurCoffre>;
}

/// Condensat SHA-1 en hexadécimal majuscule (40 caractères).
fn sha1_hex_majuscule(donnees: &[u8]) -> String {
    let condensat = Sha1::digest(donnees);
    let mut s = String::with_capacity(40);
    for octet in condensat {
        s.push(char::from_digit(u32::from(octet >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(octet & 0x0f), 16).unwrap_or('0'));
    }
    s.to_ascii_uppercase()
}

/// Nombre de fuites connues pour `mot_de_passe`, via k-anonymat.
///
/// On calcule le SHA-1, on n'envoie que les **5 premiers** caractères, et la
/// comparaison du suffixe se fait **localement**.
///
/// # Erreurs
/// [`ErreurCoffre::Fuites`] si la consultation échoue.
pub fn nombre_de_fuites(
    mot_de_passe: &str,
    fournisseur: &dyn FournisseurFuites,
) -> Result<u64, ErreurCoffre> {
    let hash = sha1_hex_majuscule(mot_de_passe.as_bytes());
    let (prefixe, suffixe) = hash.split_at(5);
    let liste = fournisseur.suffixes(prefixe)?;
    Ok(liste
        .into_iter()
        .find(|(s, _)| s.eq_ignore_ascii_case(suffixe))
        .map(|(_, n)| n)
        .unwrap_or(0))
}

/// Estime l'entropie (bits) d'un mot de passe existant d'après les classes de
/// caractères présentes. Heuristique : `log2(taille_jeu_estimé) * longueur`.
pub fn entropie_estimee(mot_de_passe: &str) -> f64 {
    let mut taille = 0usize;
    if mot_de_passe.chars().any(|c| c.is_ascii_lowercase()) {
        taille += 26;
    }
    if mot_de_passe.chars().any(|c| c.is_ascii_uppercase()) {
        taille += 26;
    }
    if mot_de_passe.chars().any(|c| c.is_ascii_digit()) {
        taille += 10;
    }
    if mot_de_passe
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace())
    {
        taille += 32;
    }
    let longueur = mot_de_passe.chars().count();
    if taille <= 1 || longueur == 0 {
        return 0.0;
    }
    (taille as f64).log2() * longueur as f64
}

/// Rapport d'audit hors-ligne : identifiants d'entrées concernées.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RapportAudit {
    /// Entrées au mot de passe faible (entropie estimée sous le seuil).
    pub faibles: Vec<String>,
    /// Entrées dont le mot de passe est réutilisé ailleurs.
    pub reutilises: Vec<String>,
    /// Entrées non modifiées depuis trop longtemps.
    pub anciens: Vec<String>,
}

/// Audite le contenu hors-ligne (aucune donnée ne quitte l'appareil).
///
/// - `entropie_min` : seuil en bits sous lequel un mot de passe est « faible » ;
/// - `age_max_secondes` : au-delà, l'entrée est « ancienne » (selon `maj_le`).
pub fn auditer(
    contenu: &ContenuCoffre,
    maintenant_unix: u64,
    age_max_secondes: u64,
    entropie_min: f64,
) -> RapportAudit {
    let mut rapport = RapportAudit::default();

    // Comptage des mots de passe pour détecter les réutilisations.
    let mut occurrences: HashMap<&str, usize> = HashMap::new();
    for e in &contenu.entrees {
        if let Some(mdp) = e.mot_de_passe.as_deref() {
            *occurrences.entry(mdp).or_insert(0) += 1;
        }
    }

    for e in &contenu.entrees {
        if let Some(mdp) = e.mot_de_passe.as_deref() {
            if entropie_estimee(mdp) < entropie_min {
                rapport.faibles.push(e.id.clone());
            }
            if occurrences.get(mdp).copied().unwrap_or(0) > 1 {
                rapport.reutilises.push(e.id.clone());
            }
        }
        if maintenant_unix.saturating_sub(e.maj_le) > age_max_secondes {
            rapport.anciens.push(e.id.clone());
        }
    }
    rapport
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modele::Entree;
    use std::cell::RefCell;

    /// Fournisseur simulé qui enregistre le préfixe reçu (pour vérifier qu'on
    /// n'envoie jamais le condensat complet).
    struct FournisseurSimule {
        suffixes: Vec<(String, u64)>,
        prefixe_recu: RefCell<Option<String>>,
    }

    impl FournisseurFuites for FournisseurSimule {
        fn suffixes(&self, prefixe: &str) -> Result<Vec<(String, u64)>, ErreurCoffre> {
            *self.prefixe_recu.borrow_mut() = Some(prefixe.to_string());
            Ok(self.suffixes.clone())
        }
    }

    #[test]
    fn k_anonymat_n_envoie_que_le_prefixe() {
        let mdp = "password";
        let hash = sha1_hex_majuscule(mdp.as_bytes());
        let (prefixe, suffixe) = hash.split_at(5);

        let fournisseur = FournisseurSimule {
            suffixes: vec![(suffixe.to_string(), 42)],
            prefixe_recu: RefCell::new(None),
        };
        let n = nombre_de_fuites(mdp, &fournisseur).unwrap();
        assert_eq!(n, 42);

        let recu = fournisseur.prefixe_recu.borrow().clone().unwrap();
        // Seul un préfixe de 5 caractères est transmis ; jamais le hash complet.
        assert_eq!(recu.len(), 5);
        assert_eq!(recu, prefixe);
        assert!(!hash.contains(&recu) || hash.starts_with(&recu));
        assert_ne!(recu, hash);
    }

    #[test]
    fn fuite_absente_renvoie_zero() {
        let fournisseur = FournisseurSimule {
            suffixes: vec![("DEADBEEF".to_string(), 7)],
            prefixe_recu: RefCell::new(None),
        };
        assert_eq!(nombre_de_fuites("autre", &fournisseur).unwrap(), 0);
    }

    #[test]
    fn entropie_estimee_coherente() {
        assert!(entropie_estimee("aaaa") < entropie_estimee("aA1!aA1!"));
        assert_eq!(entropie_estimee(""), 0.0);
    }

    #[test]
    fn audit_detecte_faibles_reutilises_anciens() {
        let mut contenu = ContenuCoffre::default();

        let mut faible = Entree::connexion("faible", "F", 1000);
        faible.mot_de_passe = Some("abc".to_string());
        contenu.entrees.push(faible);

        let mut r1 = Entree::connexion("reuse1", "R1", 1000);
        r1.mot_de_passe = Some("MotDePasseReutilise123!".to_string());
        let mut r2 = Entree::connexion("reuse2", "R2", 1000);
        r2.mot_de_passe = Some("MotDePasseReutilise123!".to_string());
        contenu.entrees.push(r1);
        contenu.entrees.push(r2);

        // maintenant = 1000 + 100 jours ; age_max = 90 jours.
        let maintenant = 1000 + 100 * 86_400;
        let rapport = auditer(&contenu, maintenant, 90 * 86_400, 50.0);

        assert!(rapport.faibles.contains(&"faible".to_string()));
        assert!(rapport.reutilises.contains(&"reuse1".to_string()));
        assert!(rapport.reutilises.contains(&"reuse2".to_string()));
        // Toutes les entrées (maj_le=1000) sont anciennes.
        assert_eq!(rapport.anciens.len(), 3);
        // Le mot de passe fort réutilisé n'est pas « faible ».
        assert!(!rapport.faibles.contains(&"reuse1".to_string()));
    }
}
