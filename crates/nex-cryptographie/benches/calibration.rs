//! Benchmarks de calibration.
//!
//! Objectif principal : calibrer les paramètres d'Argon2id pour viser ~0,5 s
//! sur la machine cible (cf. brief §3). On mesure aussi le débit des deux
//! algorithmes AEAD.
//!
//! Lancer : `cargo bench -p nex-cryptographie`.

// Les benchmarks ne sont pas du code de bibliothèque sensible : on autorise
// unwrap() pour la concision (les entrées sont fixes et maîtrisées).
#![allow(clippy::unwrap_used)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use nex_cryptographie::aead::{chiffrer, Algorithme};
use nex_cryptographie::kdf::{deriver_cle, ParametresArgon2};
use nex_cryptographie::secret::CleSecrete;

fn bench_argon2id(c: &mut Criterion) {
    let sel = [0x42u8; 16];
    let mot_de_passe = b"phrase de passe maitre de l'utilisateur";

    let mut groupe = c.benchmark_group("argon2id");
    // La dérivation est coûteuse : peu d'échantillons suffisent.
    groupe.sample_size(10);

    // (mémoire Kio, itérations, parallelisme).
    let profils = [
        (262_144u32, 3u32, 4u32), // défaut bureau : 256 Mio
        (65_536, 3, 4),           // 64 Mio
        (19_456, 2, 1),           // minimum OWASP : 19 Mio
    ];
    for (memoire, iterations, parallelisme) in profils {
        let params = ParametresArgon2::new(memoire, iterations, parallelisme);
        let etiquette = format!("m{memoire}_t{iterations}_p{parallelisme}");
        groupe.bench_function(BenchmarkId::from_parameter(etiquette), |b| {
            b.iter(|| deriver_cle(mot_de_passe, &sel, params).unwrap());
        });
    }
    groupe.finish();
}

fn bench_aead(c: &mut Criterion) {
    let cle = CleSecrete::depuis_octets([0x07u8; 32]);
    let clair = vec![0u8; 16 * 1024];

    let mut groupe = c.benchmark_group("aead_16kio");
    groupe.throughput(Throughput::Bytes(clair.len() as u64));
    for algo in [Algorithme::XChaCha20Poly1305, Algorithme::Aes256Gcm] {
        let nonce = vec![0x01u8; algo.longueur_nonce()];
        groupe.bench_function(BenchmarkId::from_parameter(format!("{algo:?}")), |b| {
            b.iter(|| chiffrer(algo, &cle, &nonce, &clair, b"").unwrap());
        });
    }
    groupe.finish();
}

criterion_group!(benches, bench_argon2id, bench_aead);
criterion_main!(benches);
