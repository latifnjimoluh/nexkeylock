//! Tests d'intégration de la sauvegarde/récupération : les **deux voies** de
//! déballage de la DEK (mot de passe maître et code de récupération).

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use nex_coffre::{
    nouvel_identifiant, CoffreDeverrouille, CoffreVerrouille, Entree, ErreurCoffre,
    ParametresArgon2,
};

fn params() -> ParametresArgon2 {
    ParametresArgon2::new(8, 1, 1)
}

fn coffre_temp() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let chemin = dir.path().join("coffre.vault");
    (dir, chemin)
}

#[test]
fn deux_voies_de_deballage() {
    let (_dir, chemin) = coffre_temp();
    let mdp = b"mot de passe maitre";

    let mut coffre = CoffreDeverrouille::creer(&chemin, mdp, params()).unwrap();
    let id = nouvel_identifiant().unwrap();
    coffre.ajouter(Entree::connexion(&id, "Site", 0));
    coffre.enregistrer().unwrap();

    assert!(!coffre.a_recuperation());
    let code = coffre.activer_recuperation(params()).unwrap();
    assert!(coffre.a_recuperation());

    // Voie 1 : mot de passe maître.
    let par_mdp = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(mdp)
        .unwrap();
    assert_eq!(par_mdp.obtenir(&id).unwrap().nom, "Site");

    // Voie 2 : code de récupération.
    let par_code = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller_par_recuperation(&code)
        .unwrap();
    assert_eq!(par_code.obtenir(&id).unwrap().nom, "Site");
}

#[test]
fn mauvais_code_rejete() {
    let (_dir, chemin) = coffre_temp();
    let mut coffre = CoffreDeverrouille::creer(&chemin, b"mdp", params()).unwrap();
    coffre.activer_recuperation(params()).unwrap();

    let erreur = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller_par_recuperation("00000-00000-00000-00000")
        .unwrap_err();
    assert!(matches!(erreur, ErreurCoffre::MotDePasseInvalide));
}

#[test]
fn sans_recuperation_configuree() {
    let (_dir, chemin) = coffre_temp();
    CoffreDeverrouille::creer(&chemin, b"mdp", params()).unwrap();

    let erreur = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller_par_recuperation("peu-importe")
        .unwrap_err();
    assert!(matches!(erreur, ErreurCoffre::RecuperationAbsente));
}

#[test]
fn recuperation_survit_au_changement_de_mot_de_passe() {
    let (_dir, chemin) = coffre_temp();
    let ancien = b"ancien";
    let nouveau = b"nouveau";

    let mut coffre = CoffreDeverrouille::creer(&chemin, ancien, params()).unwrap();
    let code = coffre.activer_recuperation(params()).unwrap();
    coffre.changer_mot_de_passe(nouveau).unwrap();

    // Le code de récupération fonctionne toujours.
    assert!(CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller_par_recuperation(&code)
        .is_ok());
    // Le nouveau mot de passe aussi.
    assert!(CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(nouveau)
        .is_ok());
}

#[test]
fn bloc_recuperation_corrompu_n_affecte_pas_le_mot_de_passe() {
    use nex_coffre::format::FichierCoffre;

    let (_dir, chemin) = coffre_temp();
    let mdp = b"mdp";
    let mut coffre = CoffreDeverrouille::creer(&chemin, mdp, params()).unwrap();
    let code = coffre.activer_recuperation(params()).unwrap();

    // Corrompt le bloc de récupération.
    let donnees = std::fs::read(&chemin).unwrap();
    let mut fichier = FichierCoffre::decoder(&donnees).unwrap();
    let dernier = fichier.recuperation.len() - 1;
    fichier.recuperation[dernier] ^= 0xFF;
    std::fs::write(&chemin, fichier.encoder()).unwrap();

    // La récupération échoue proprement…
    assert!(CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller_par_recuperation(&code)
        .is_err());
    // …mais le mot de passe maître fonctionne toujours.
    assert!(CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(mdp)
        .is_ok());
}
