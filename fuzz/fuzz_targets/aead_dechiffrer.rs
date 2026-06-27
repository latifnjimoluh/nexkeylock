#![no_main]
//! Cible de fuzz : la routine de déchiffrement AEAD sur entrée arbitraire.
//! Le déchiffrement doit renvoyer une erreur (jamais de `panic`) sur des
//! données non authentifiées.

use libfuzzer_sys::fuzz_target;
use nex_cryptographie::aead::{dechiffrer, Algorithme};
use nex_cryptographie::CleSecrete;

fuzz_target!(|donnees: &[u8]| {
    // 32 octets de clé + au moins un octet de reste.
    if donnees.len() < 33 {
        return;
    }
    let mut cle_octets = [0u8; 32];
    cle_octets.copy_from_slice(&donnees[..32]);
    let cle = CleSecrete::depuis_octets(cle_octets);
    let reste = &donnees[32..];

    for algo in [Algorithme::XChaCha20Poly1305, Algorithme::Aes256Gcm] {
        let n = algo.longueur_nonce();
        if reste.len() < n {
            continue;
        }
        let (nonce, chiffre) = reste.split_at(n);
        // Doit échouer proprement (texte non authentifié), sans paniquer.
        let _ = dechiffrer(algo, &cle, nonce, chiffre, b"");
    }
});
