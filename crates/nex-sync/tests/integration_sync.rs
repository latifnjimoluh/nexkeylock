//! Intégration coffre + synchro : un coffre chiffré transite par un dépôt
//! zéro-connaissance (qui ne voit que des octets opaques) et est rouvert
//! intact par un second client.

#![allow(clippy::unwrap_used)]

use nex_coffre::{
    nouvel_identifiant, CoffreDeverrouille, CoffreVerrouille, Entree, ParametresArgon2,
};
use nex_sync::{DepotMemoire, DepotSync, EtatLocal, Pousser};

/// Recherche naïve d'une sous-séquence d'octets.
fn contient(foin: &[u8], aiguille: &[u8]) -> bool {
    foin.windows(aiguille.len()).any(|f| f == aiguille)
}

#[test]
fn synchronisation_d_un_coffre_chiffre() {
    let dir = tempfile::tempdir().unwrap();
    let chemin_a = dir.path().join("a.vault");
    let chemin_b = dir.path().join("b.vault");
    let mdp = b"mot de passe maitre";
    let params = ParametresArgon2::new(8, 1, 1);

    // Client A crée un coffre avec une entrée.
    {
        let mut coffre = CoffreDeverrouille::creer(&chemin_a, mdp, params).unwrap();
        let mut entree = Entree::connexion(nouvel_identifiant().unwrap(), "Banque secrete", 0);
        entree.mot_de_passe = Some("motdepasse-entree".to_string());
        coffre.ajouter(entree);
        coffre.enregistrer().unwrap();
    }
    let blob = std::fs::read(&chemin_a).unwrap();

    // A pousse le blob chiffré au dépôt.
    let mut depot = DepotMemoire::default();
    let mut etat_a = EtatLocal::default();
    assert_eq!(etat_a.pousser(&mut depot, &blob), Pousser::Accepte(1));

    // Le dépôt ne contient que du chiffré : ni le nom d'entrée ni le mot de
    // passe d'entrée n'apparaissent en clair.
    let stocke = depot.tirer().unwrap().blob;
    assert!(!contient(&stocke, b"Banque secrete"));
    assert!(!contient(&stocke, b"motdepasse-entree"));

    // Client B tire le blob, l'installe et ouvre le coffre intact.
    let mut etat_b = EtatLocal::default();
    let recu = etat_b.tirer(&depot).unwrap();
    std::fs::write(&chemin_b, &recu.blob).unwrap();

    let coffre_b = CoffreVerrouille::ouvrir(&chemin_b)
        .unwrap()
        .deverrouiller(mdp)
        .unwrap();
    assert_eq!(coffre_b.entrees().len(), 1);
    assert_eq!(coffre_b.entrees()[0].nom, "Banque secrete");
    assert_eq!(
        coffre_b.entrees()[0].mot_de_passe.as_deref(),
        Some("motdepasse-entree")
    );
}
