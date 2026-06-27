//! Intégration coffre + partage : le coffre stocke l'identité de partage, et
//! après réouverture cette identité permet de recevoir un message chiffré de
//! bout en bout.

#![allow(clippy::unwrap_used)]

use nex_coffre::{CoffreDeverrouille, CoffreVerrouille, ParametresArgon2};
use nex_partage::{generer_paire, partager, recevoir, ClesPrivees, ClesPubliques, MessagePartage};

#[test]
fn identite_de_partage_persistee_dans_le_coffre() {
    let dir = tempfile::tempdir().unwrap();
    let chemin = dir.path().join("coffre.vault");
    let mdp = b"mot de passe maitre";
    let params = ParametresArgon2::new(8, 1, 1);

    // Génère une identité de partage et stocke ses clés privées dans le coffre.
    let (prive, public) = generer_paire();
    let octets_public = public.vers_octets();
    {
        let mut coffre = CoffreDeverrouille::creer(&chemin, mdp, params).unwrap();
        assert!(coffre.identite_partage().is_none());
        coffre.definir_identite_partage(prive.vers_octets().to_vec());
        coffre.enregistrer().unwrap();
    }

    // Un tiers chiffre un secret vers le bundle public (qu'il a reçu).
    let public_tiers = ClesPubliques::depuis_octets(&octets_public).unwrap();
    let message = partager(&public_tiers, b"secret partage de bout en bout")
        .unwrap()
        .vers_octets();

    // On rouvre le coffre, recharge l'identité, et déchiffre le message.
    let coffre = CoffreVerrouille::ouvrir(&chemin)
        .unwrap()
        .deverrouiller(mdp)
        .unwrap();
    let octets_prive = coffre.identite_partage().expect("identité présente");
    let prive_recharge = ClesPrivees::depuis_octets(octets_prive).unwrap();
    let msg = MessagePartage::depuis_octets(&message).unwrap();
    let recu = recevoir(&prive_recharge, &msg).unwrap();

    assert_eq!(recu, b"secret partage de bout en bout");
}
