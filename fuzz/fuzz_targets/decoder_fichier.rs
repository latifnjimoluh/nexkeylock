#![no_main]
//! Cible de fuzz : le décodeur de format de coffre sur entrée arbitraire.
//! Objectif : aucun `panic`, aucun comportement indéfini.

use libfuzzer_sys::fuzz_target;
use nex_coffre::format::FichierCoffre;

fuzz_target!(|donnees: &[u8]| {
    // Le décodeur doit échouer proprement (Err) sans jamais paniquer.
    let _ = FichierCoffre::decoder(donnees);
});
