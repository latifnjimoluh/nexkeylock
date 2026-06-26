//! Tests d'intégration du cycle de vie complet du coffre et des cas
//! adversariaux (mauvais mot de passe, corruption, downgrade) — fail-closed,
//! sans aucun `panic`.

// Code de test : unwrap() est idiomatique dans les fonctions utilitaires.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use nex_coffre::{
    maintenant_unix, nouvel_identifiant, Algorithme, CoffreDeverrouille, CoffreVerrouille, Entree,
    ErreurCoffre, ParametresArgon2,
};

/// Paramètres Argon2id légers pour des tests rapides.
fn params() -> ParametresArgon2 {
    ParametresArgon2::new(8, 1, 1)
}

/// Crée un répertoire temporaire et un chemin de coffre à l'intérieur.
fn coffre_temp() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let chemin = dir.path().join("coffre.vault");
    (dir, chemin)
}

#[test]
fn cycle_de_vie_complet() {
    let (_dir, chemin) = coffre_temp();
    let mdp = b"phrase de passe maitre robuste";

    // Créer + ajouter.
    let mut coffre = CoffreDeverrouille::creer(&chemin, mdp, params()).unwrap();
    let id = nouvel_identifiant().unwrap();
    let mut entree = Entree::connexion(&id, "Banque", maintenant_unix());
    entree.nom_utilisateur = Some("jean.dupont".to_string());
    entree.mot_de_passe = Some("s3cr3t-initial".to_string());
    coffre.ajouter(entree);
    coffre.enregistrer().unwrap();

    // Verrouiller (efface les clés) puis déverrouiller.
    let verrou = coffre.verrouiller().unwrap();
    let mut coffre = verrou.deverrouiller(mdp).unwrap();

    // Lire.
    let lu = coffre.obtenir(&id).unwrap();
    assert_eq!(lu.nom, "Banque");
    assert_eq!(lu.mot_de_passe.as_deref(), Some("s3cr3t-initial"));

    // Modifier.
    coffre.modifier(&id).unwrap().mot_de_passe = Some("s3cr3t-modifie".to_string());
    assert!(!coffre.supprimer("identifiant-inexistant"));
    coffre.enregistrer().unwrap();

    // Rouvrir depuis le disque : la modification a persisté.
    let mut coffre = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(mdp)
        .unwrap();
    assert_eq!(
        coffre.obtenir(&id).unwrap().mot_de_passe.as_deref(),
        Some("s3cr3t-modifie")
    );

    // Supprimer puis vérifier le vide après réouverture.
    assert!(coffre.supprimer(&id));
    coffre.enregistrer().unwrap();
    let coffre = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(mdp)
        .unwrap();
    assert!(coffre.entrees().is_empty());
}

#[test]
fn mauvais_mot_de_passe_rejete_sans_fuite() {
    let (_dir, chemin) = coffre_temp();
    CoffreDeverrouille::creer(&chemin, b"le bon mot de passe", params()).unwrap();

    let verrou = CoffreVerrouille::ouvrir(&chemin).unwrap();
    let erreur = verrou
        .deverrouiller(b"un mauvais mot de passe")
        .unwrap_err();
    assert!(matches!(erreur, ErreurCoffre::MotDePasseInvalide));
}

#[test]
fn corps_corrompu_echoue_proprement() {
    let (_dir, chemin) = coffre_temp();
    CoffreDeverrouille::creer(&chemin, b"mdp", params()).unwrap();

    // Altère le dernier octet (tag du corps).
    let mut donnees = std::fs::read(&chemin).unwrap();
    let dernier = donnees.len() - 1;
    donnees[dernier] ^= 0xFF;
    std::fs::write(&chemin, &donnees).unwrap();

    let erreur = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(b"mdp")
        .unwrap_err();
    assert!(matches!(erreur, ErreurCoffre::Corrompu));
}

#[test]
fn coffre_tronque_echoue_proprement() {
    let (_dir, chemin) = coffre_temp();
    CoffreDeverrouille::creer(&chemin, b"mdp", params()).unwrap();
    let donnees = std::fs::read(&chemin).unwrap();

    for n in [0usize, 4, 8, donnees.len() / 2, donnees.len() - 1] {
        std::fs::write(&chemin, &donnees[..n]).unwrap();
        // Aucun panic, toujours une erreur typée.
        assert!(CoffreVerrouille::ouvrir(&chemin).is_err());
    }
}

#[test]
fn magie_corrompue_rejetee() {
    let (_dir, chemin) = coffre_temp();
    CoffreDeverrouille::creer(&chemin, b"mdp", params()).unwrap();

    let mut donnees = std::fs::read(&chemin).unwrap();
    donnees[0] ^= 0xFF;
    std::fs::write(&chemin, &donnees).unwrap();

    assert!(matches!(
        CoffreVerrouille::ouvrir(&chemin),
        Err(ErreurCoffre::FormatInvalide)
    ));
}

#[test]
fn changement_de_mot_de_passe_reemballe_la_dek() {
    let (_dir, chemin) = coffre_temp();
    let ancien = b"ancien mot de passe maitre";
    let nouveau = b"nouveau mot de passe maitre";

    let mut coffre = CoffreDeverrouille::creer(&chemin, ancien, params()).unwrap();
    let id = nouvel_identifiant().unwrap();
    coffre.ajouter(Entree::connexion(&id, "Site", maintenant_unix()));
    coffre.enregistrer().unwrap();

    let sel_avant = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .entete()
        .sel
        .clone();
    coffre.changer_mot_de_passe(nouveau).unwrap();
    let sel_apres = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .entete()
        .sel
        .clone();

    // Réemballage : un nouveau sel a été tiré.
    assert_ne!(sel_avant, sel_apres);

    // L'ancien mot de passe est rejeté.
    assert!(matches!(
        CoffreVerrouille::ouvrir(&chemin)
            .unwrap()
            .deverrouiller(ancien),
        Err(ErreurCoffre::MotDePasseInvalide)
    ));

    // Le nouveau fonctionne et le contenu est préservé.
    let coffre = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(nouveau)
        .unwrap();
    assert_eq!(coffre.obtenir(&id).unwrap().nom, "Site");
}

#[test]
fn downgrade_de_version_rejete() {
    use nex_coffre::format::FichierCoffre;

    let (_dir, chemin) = coffre_temp();
    CoffreDeverrouille::creer(&chemin, b"mdp", params()).unwrap();

    let donnees = std::fs::read(&chemin).unwrap();
    let mut fichier = FichierCoffre::decoder(&donnees).unwrap();
    fichier.entete.version = 0; // tentative de downgrade
    fichier.entete_brut = fichier.entete.aad_dek().unwrap();
    std::fs::write(&chemin, fichier.encoder()).unwrap();

    assert!(matches!(
        CoffreVerrouille::ouvrir(&chemin),
        Err(ErreurCoffre::VersionNonSupportee(0))
    ));
}

#[test]
fn substitution_d_algorithme_rejetee() {
    use nex_coffre::format::FichierCoffre;

    let (_dir, chemin) = coffre_temp();
    CoffreDeverrouille::creer(&chemin, b"mdp", params()).unwrap();

    let donnees = std::fs::read(&chemin).unwrap();
    let mut fichier = FichierCoffre::decoder(&donnees).unwrap();
    // Prétendre que le coffre est en AES-256-GCM alors qu'il a été créé en
    // XChaCha20 : l'AAD et la longueur de nonce ne correspondent plus.
    fichier.entete.algorithme = Algorithme::Aes256Gcm.identifiant();
    fichier.entete_brut = fichier.entete.aad_dek().unwrap();
    std::fs::write(&chemin, fichier.encoder()).unwrap();

    let erreur = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(b"mdp")
        .unwrap_err();
    assert!(matches!(erreur, ErreurCoffre::MotDePasseInvalide));
}
