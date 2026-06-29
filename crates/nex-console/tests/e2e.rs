//! Tests end-to-end de la CLI (`assert_cmd`).
//!
//! Le mot de passe maître est fourni via `NEXKEYLOCK_MDP` et les paramètres
//! Argon2id allégés via `NEXKEYLOCK_KDF_RAPIDE` (rapidité des tests). On vérifie
//! aussi qu'**aucun secret maître** n'apparaît dans la sortie.

// Code de test : unwrap() est idiomatique dans les fonctions utilitaires.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

/// Construit une commande `nexkeylock` avec coffre, mot de passe maître et KDF
/// rapide.
fn cmd(coffre: &Path, mdp: &str) -> Command {
    let mut c = Command::cargo_bin("nexkeylock").unwrap();
    c.env("NEXKEYLOCK_KDF_RAPIDE", "1")
        .env("NEXKEYLOCK_MDP", mdp)
        .arg("--coffre")
        .arg(coffre);
    c
}

const MDP: &str = "MotDePasseMaitreDeTest";

#[test]
fn init_unlock_add_list_get() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");

    cmd(&coffre, MDP)
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("Coffre créé"));

    cmd(&coffre, MDP)
        .arg("unlock")
        .assert()
        .success()
        .stdout(predicate::str::contains("0 entrée"))
        .stdout(predicate::str::contains(MDP).not());

    cmd(&coffre, MDP)
        .args([
            "add",
            "Banque",
            "--utilisateur",
            "jean",
            "--generer",
            "--longueur",
            "24",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Entrée ajoutée"));

    // `list` montre le nom et l'utilisateur, jamais un mot de passe d'entrée.
    cmd(&coffre, MDP)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Banque"))
        .stdout(predicate::str::contains("jean"))
        .stdout(predicate::str::contains("Mot de passe").not())
        .stdout(predicate::str::contains(MDP).not());

    // `get` révèle le mot de passe de l'entrée (jamais le mot de passe maître).
    cmd(&coffre, MDP)
        .args(["get", "Banque"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Mot de passe :"))
        .stdout(predicate::str::contains("jean"))
        .stdout(predicate::str::contains(MDP).not());
}

#[test]
fn mauvais_mot_de_passe_echoue() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    cmd(&coffre, MDP).arg("init").assert().success();

    cmd(&coffre, "mauvais-mot-de-passe")
        .arg("unlock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalide"))
        .stderr(predicate::str::contains("mauvais-mot-de-passe").not());
}

#[test]
fn fichier_cle_second_facteur() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    let kf = dir.path().join("ma.cle");

    // Génère le fichier-clé.
    Command::cargo_bin("nexkeylock")
        .unwrap()
        .env("NEXKEYLOCK_SANS_VERIF_MAJ", "1")
        .arg("generer-fichier-cle")
        .arg(&kf)
        .assert()
        .success();
    assert!(kf.exists());

    // Création avec fichier-clé.
    cmd(&coffre, MDP)
        .arg("--fichier-cle")
        .arg(&kf)
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("fichier-clé"));

    // Déverrouillage AVEC le fichier-clé => succès.
    cmd(&coffre, MDP)
        .arg("--fichier-cle")
        .arg(&kf)
        .arg("unlock")
        .assert()
        .success()
        .stdout(predicate::str::contains("déverrouillé"));

    // Déverrouillage SANS le fichier-clé => échec sûr.
    cmd(&coffre, MDP)
        .arg("unlock")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalide"));
}

#[test]
fn generate_sans_coffre() {
    Command::cargo_bin("nexkeylock")
        .unwrap()
        .env("NEXKEYLOCK_SANS_VERIF_MAJ", "1")
        .args(["generate", "--longueur", "30"])
        .assert()
        .success()
        .stdout(predicate::function(|s: &str| {
            s.trim().chars().count() == 30
        }));

    Command::cargo_bin("nexkeylock")
        .unwrap()
        .env("NEXKEYLOCK_SANS_VERIF_MAJ", "1")
        .args(["generate", "--mots", "6"])
        .assert()
        .success()
        .stdout(predicate::str::contains('-'))
        .stderr(predicate::str::contains("Entropie"));
}

#[test]
fn export_puis_import() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.vault");
    let export = dir.path().join("export.vault");
    let cible = dir.path().join("cible.vault");

    cmd(&source, MDP).arg("init").assert().success();
    cmd(&source, MDP)
        .args(["add", "Courriel", "--generer"])
        .assert()
        .success();
    cmd(&source, MDP)
        .arg("export")
        .arg(&export)
        .assert()
        .success()
        .stdout(predicate::str::contains("exporté"));

    cmd(&cible, MDP)
        .arg("import")
        .arg(&export)
        .assert()
        .success()
        .stdout(predicate::str::contains("importé"));

    cmd(&cible, MDP)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Courriel"));
}

#[test]
fn changement_de_mot_de_passe() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    cmd(&coffre, "ancien-mot-de-passe")
        .arg("init")
        .assert()
        .success();

    // change-password lit l'ancien puis le nouveau sur l'entrée standard.
    Command::cargo_bin("nexkeylock")
        .unwrap()
        .env("NEXKEYLOCK_KDF_RAPIDE", "1")
        .env_remove("NEXKEYLOCK_MDP")
        .arg("--coffre")
        .arg(&coffre)
        .arg("change-password")
        .write_stdin("ancien-mot-de-passe\nnouveau-mot-de-passe\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("changé"));

    // Le nouveau mot de passe fonctionne.
    cmd(&coffre, "nouveau-mot-de-passe")
        .arg("unlock")
        .assert()
        .success();

    // L'ancien est rejeté.
    cmd(&coffre, "ancien-mot-de-passe")
        .arg("unlock")
        .assert()
        .failure();
}

#[test]
fn totp_et_audit() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    cmd(&coffre, MDP).arg("init").assert().success();

    // Secret TOTP = graine RFC 6238 encodée en Base32.
    cmd(&coffre, MDP)
        .args([
            "add",
            "GitHub",
            "--generer",
            "--totp",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        ])
        .assert()
        .success();

    cmd(&coffre, MDP)
        .args(["totp", "GitHub"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d{6}").unwrap())
        .stdout(predicate::str::contains("valide encore"));

    cmd(&coffre, MDP)
        .arg("audit")
        .assert()
        .success()
        .stdout(predicate::str::contains("Mots de passe faibles"));
}

#[test]
fn recuperation_setup_et_reset() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    cmd(&coffre, "ancien-maitre").arg("init").assert().success();
    cmd(&coffre, "ancien-maitre")
        .args(["add", "Test", "--generer"])
        .assert()
        .success();

    // `recovery-setup` affiche le code une seule fois.
    let sortie = cmd(&coffre, "ancien-maitre")
        .arg("recovery-setup")
        .output()
        .unwrap();
    assert!(sortie.status.success());
    let texte = String::from_utf8_lossy(&sortie.stdout);
    let code = texte
        .lines()
        .map(str::trim)
        .find(|l| l.len() == 47 && l.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
        .expect("code de récupération introuvable dans la sortie")
        .to_string();

    // `recovery-reset` : restaure l'accès et fixe un nouveau mot de passe.
    Command::cargo_bin("nexkeylock")
        .unwrap()
        .env("NEXKEYLOCK_KDF_RAPIDE", "1")
        .env("NEXKEYLOCK_CODE", &code)
        .env("NEXKEYLOCK_MDP", "nouveau-maitre")
        .arg("--coffre")
        .arg(&coffre)
        .arg("recovery-reset")
        .assert()
        .success()
        .stdout(predicate::str::contains("restauré"));

    // Le nouveau mot de passe fonctionne, le contenu est préservé…
    cmd(&coffre, "nouveau-maitre")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("Test"));
    // …et l'ancien est rejeté.
    cmd(&coffre, "ancien-maitre")
        .arg("unlock")
        .assert()
        .failure();
}

#[test]
fn export_en_clair_protege_par_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    cmd(&coffre, MDP).arg("init").assert().success();
    cmd(&coffre, MDP)
        .args(["add", "Compte", "--generer"])
        .assert()
        .success();

    let clair = dir.path().join("clair.bin");
    // Refusé sans confirmation explicite.
    cmd(&coffre, MDP)
        .arg("export")
        .arg(&clair)
        .arg("--en-clair")
        .assert()
        .failure()
        .stderr(predicate::str::contains("je-confirme-le-risque"));
    assert!(!clair.exists());

    // Accepté avec confirmation explicite.
    cmd(&coffre, MDP)
        .arg("export")
        .arg(&clair)
        .arg("--en-clair")
        .arg("--je-confirme-le-risque")
        .assert()
        .success()
        .stderr(predicate::str::contains("EN CLAIR"));
    assert!(clair.exists());

    // Export chiffré par défaut : le fichier porte la magie du format.
    let chiffre = dir.path().join("chiffre.vault");
    cmd(&coffre, MDP)
        .arg("export")
        .arg(&chiffre)
        .assert()
        .success()
        .stdout(predicate::str::contains("chiffré"));
    let octets = std::fs::read(&chiffre).unwrap();
    assert_eq!(&octets[..8], b"NEXKLCK1");
}

#[test]
fn rm_supprime_l_entree() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    cmd(&coffre, MDP).arg("init").assert().success();
    cmd(&coffre, MDP)
        .args(["add", "Jetable", "--generer"])
        .assert()
        .success();

    // Récupère l'identifiant via la recherche d'abord (get).
    cmd(&coffre, MDP).args(["rm", "Jetable"]).assert().failure(); // rm attend un identifiant exact, pas un nom.

    // Liste pour récupérer l'identifiant, puis suppression par identifiant.
    let sortie = cmd(&coffre, MDP).arg("list").output().unwrap();
    let texte = String::from_utf8_lossy(&sortie.stdout);
    let id = texte.split_whitespace().next().unwrap().to_string();

    cmd(&coffre, MDP)
        .args(["rm", &id])
        .assert()
        .success()
        .stdout(predicate::str::contains("supprimée"));

    cmd(&coffre, MDP)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("coffre vide"));
}
