//! Tests de propriétés du coffre : aller-retour de sérialisation et robustesse
//! à l'altération d'un octet quelconque du fichier.

// Code de test : unwrap() est idiomatique dans les fonctions utilitaires.
#![allow(clippy::unwrap_used)]

use nex_coffre::{CoffreDeverrouille, CoffreVerrouille, Entree, ParametresArgon2};
use proptest::prelude::*;

fn params() -> ParametresArgon2 {
    ParametresArgon2::new(8, 1, 1)
}

proptest! {
    /// Tout ce qui est ajouté est relu à l'identique après sauvegarde et
    /// réouverture.
    #[test]
    fn aller_retour_du_contenu(noms in proptest::collection::vec("[a-zA-Z0-9 ]{1,12}", 0..8)) {
        let dir = tempfile::tempdir().unwrap();
        let chemin = dir.path().join("coffre.vault");
        let mdp = b"mot de passe de test";

        let mut coffre = CoffreDeverrouille::creer(&chemin, mdp, params()).unwrap();
        let mut attendus = Vec::new();
        for (k, nom) in noms.iter().enumerate() {
            let id = format!("id-{k}");
            let mut e = Entree::connexion(&id, nom, 0);
            e.mot_de_passe = Some(format!("pwd-{nom}"));
            coffre.ajouter(e);
            attendus.push((id, nom.clone()));
        }
        coffre.enregistrer().unwrap();

        let coffre = CoffreVerrouille::ouvrir(&chemin).unwrap().deverrouiller(mdp).unwrap();
        prop_assert_eq!(coffre.entrees().len(), noms.len());
        for (id, nom) in &attendus {
            let e = coffre.obtenir(id).unwrap();
            prop_assert_eq!(&e.nom, nom);
            let attendu = format!("pwd-{nom}");
            prop_assert_eq!(e.mot_de_passe.as_deref(), Some(attendu.as_str()));
        }
    }

    /// L'altération d'un seul bit, où qu'il soit dans le fichier, fait échouer
    /// l'ouverture ou le déverrouillage — jamais de `panic`, jamais de donnée.
    #[test]
    fn toute_alteration_d_un_bit_echoue(index in any::<usize>(), bit in 0u32..8) {
        let dir = tempfile::tempdir().unwrap();
        let chemin = dir.path().join("coffre.vault");
        let mdp = b"mot de passe de test";

        CoffreDeverrouille::creer(&chemin, mdp, params()).unwrap();
        let mut donnees = std::fs::read(&chemin).unwrap();
        let i = index % donnees.len();
        donnees[i] ^= 1u8 << bit;
        std::fs::write(&chemin, &donnees).unwrap();

        let resultat = CoffreVerrouille::ouvrir(&chemin).and_then(|v| v.deverrouiller(mdp));
        prop_assert!(resultat.is_err());
    }
}
