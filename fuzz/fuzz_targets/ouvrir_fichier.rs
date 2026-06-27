#![no_main]
//! Cible de fuzz : décodage + validation d'en-tête + ré-encodage.
//! Un fichier décodé doit pouvoir être validé et ré-encodé sans `panic`.

use libfuzzer_sys::fuzz_target;
use nex_coffre::format::FichierCoffre;

fuzz_target!(|donnees: &[u8]| {
    if let Ok(fichier) = FichierCoffre::decoder(donnees) {
        let _ = fichier.entete.valider();
        // Le ré-encodage d'une structure décodée ne doit jamais paniquer.
        let _ = fichier.encoder();
    }
});
