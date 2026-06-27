//! Tests end-to-end des commandes avancées : `share`, `emergency`, `passkey`.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

fn cmd(coffre: &Path, mdp: &str) -> Command {
    let mut c = Command::cargo_bin("nexkeylock").unwrap();
    c.env("NEXKEYLOCK_KDF_RAPIDE", "1")
        .env("NEXKEYLOCK_MDP", mdp)
        .arg("--coffre")
        .arg(coffre);
    c
}

#[test]
fn partage_entre_deux_coffres() {
    let dir = tempfile::tempdir().unwrap();
    let coffre_a = dir.path().join("a.vault"); // expéditeur
    let coffre_b = dir.path().join("b.vault"); // destinataire
    let bundle_b = dir.path().join("bundle_b.bin");
    let message = dir.path().join("message.bin");

    // Le destinataire B publie son bundle public.
    cmd(&coffre_b, "mdp-b").arg("init").assert().success();
    cmd(&coffre_b, "mdp-b")
        .args(["share", "identity", "--sortie"])
        .arg(&bundle_b)
        .assert()
        .success();

    // L'expéditeur A crée une entrée avec un mot de passe connu.
    cmd(&coffre_a, "mdp-a").arg("init").assert().success();
    cmd(&coffre_a, "mdp-a")
        .arg("add")
        .arg("Compte")
        .write_stdin("motdepasse-a-partager\n")
        .assert()
        .success();

    // A scelle le mot de passe de l'entrée vers le bundle de B.
    cmd(&coffre_a, "mdp-a")
        .args(["share", "send", "--entree", "Compte", "--destinataire"])
        .arg(&bundle_b)
        .arg("--sortie")
        .arg(&message)
        .assert()
        .success();

    // B ouvre le message et révèle le secret partagé.
    cmd(&coffre_b, "mdp-b")
        .args(["share", "receive", "--fichier"])
        .arg(&message)
        .assert()
        .success()
        .stdout(predicate::str::contains("motdepasse-a-partager"));
}

#[test]
fn acces_d_urgence_avec_delai() {
    let dir = tempfile::tempdir().unwrap();
    let coffre_contact = dir.path().join("contact.vault");
    let bundle = dir.path().join("bundle.bin");
    let acces = dir.path().join("acces.bin");
    let delai = 7u64 * 86_400;

    // Le contact publie son bundle.
    cmd(&coffre_contact, "mdp").arg("init").assert().success();
    cmd(&coffre_contact, "mdp")
        .args(["share", "identity", "--sortie"])
        .arg(&bundle)
        .assert()
        .success();

    // Le propriétaire scelle un matériel d'accès vers le contact (7 jours).
    cmd(&coffre_contact, "mdp")
        .args(["emergency", "seal", "--delai-jours", "7", "--contact"])
        .arg(&bundle)
        .arg("--sortie")
        .arg(&acces)
        .write_stdin("code-urgence-secret\n")
        .assert()
        .success();

    // Avant l'échéance : accès refusé.
    cmd(&coffre_contact, "mdp")
        .args([
            "emergency",
            "open",
            "--depuis",
            "1000",
            "--maintenant",
            "1000",
            "--fichier",
        ])
        .arg(&acces)
        .assert()
        .failure()
        .stderr(predicate::str::contains("délai"));

    // À l'échéance : accès accordé, matériel révélé.
    let maintenant = (1000 + delai).to_string();
    cmd(&coffre_contact, "mdp")
        .args([
            "emergency",
            "open",
            "--depuis",
            "1000",
            "--maintenant",
            &maintenant,
            "--fichier",
        ])
        .arg(&acces)
        .assert()
        .success()
        .stdout(predicate::str::contains("code-urgence-secret"));
}

#[test]
fn passkey_creation_et_assertion() {
    let dir = tempfile::tempdir().unwrap();
    let coffre = dir.path().join("c.vault");
    cmd(&coffre, "mdp").arg("init").assert().success();

    cmd(&coffre, "mdp")
        .args(["passkey", "create", "exemple.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Clé publique"));

    cmd(&coffre, "mdp")
        .args(["passkey", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("exemple.com"));

    // Première assertion : compteur 1.
    cmd(&coffre, "mdp")
        .args([
            "passkey",
            "assert",
            "exemple.com",
            "--defi",
            "0a0b0c",
            "--origine",
            "https://exemple.com",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("signature"))
        .stdout(predicate::str::contains("compteur           : 1"));

    // Seconde assertion : le compteur a été persisté (2).
    cmd(&coffre, "mdp")
        .args([
            "passkey",
            "assert",
            "exemple.com",
            "--defi",
            "0a0b0c",
            "--origine",
            "https://exemple.com",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("compteur           : 2"));

    // Assertion pour un site sans passkey : échec propre.
    cmd(&coffre, "mdp")
        .args([
            "passkey",
            "assert",
            "inconnu.com",
            "--defi",
            "00",
            "--origine",
            "https://inconnu.com",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("aucune passkey"));
}
