//! Serveur HTTP de synchronisation zéro-connaissance (binaire).
//!
//! Couche réseau mince autour de [`nex_serveur_sync::traiter`]. État **en
//! mémoire** (réinitialisé au redémarrage) : suffisant pour le développement
//! local et les tests. La persistance disque et le **TLS** relèvent du
//! déploiement (jalon S7) ; en local, à placer derrière un proxy TLS.

use std::sync::Mutex;

use nex_serveur_sync::{traiter, EtatServeur, Reponse, Requete};

fn main() {
    let adresse =
        std::env::var("NEXKEYLOCK_SYNC_ADRESSE").unwrap_or_else(|_| "127.0.0.1:8787".to_string());

    let serveur = match tiny_http::Server::http(&adresse) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Démarrage impossible sur {adresse} : {e}");
            std::process::exit(1);
        }
    };
    eprintln!("nexkeylock-serveur-sync à l'écoute sur http://{adresse} (zéro-connaissance)");

    let etat = Mutex::new(EtatServeur::default());

    for mut requete in serveur.incoming_requests() {
        let methode = format!("{}", requete.method());
        let chemin = requete.url().split('?').next().unwrap_or("").to_string();
        let jeton = requete
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .and_then(|h| h.value.as_str().strip_prefix("Bearer ").map(str::to_string));

        let mut corps = Vec::new();
        if requete.as_reader().read_to_end(&mut corps).is_err() {
            let _ = requete.respond(vers_http(&Reponse {
                code: 400,
                corps: br#"{"erreur":"corps illisible"}"#.to_vec(),
            }));
            continue;
        }

        let reponse = match etat.lock() {
            Ok(mut garde) => traiter(
                &mut garde,
                &Requete {
                    methode,
                    chemin,
                    jeton,
                    corps,
                },
            ),
            Err(_) => Reponse {
                code: 500,
                corps: br#"{"erreur":"etat indisponible"}"#.to_vec(),
            },
        };
        let _ = requete.respond(vers_http(&reponse));
    }
}

/// Convertit une [`Reponse`] applicative en réponse HTTP `tiny_http`.
fn vers_http(reponse: &Reponse) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let mut http = tiny_http::Response::from_data(reponse.corps.clone())
        .with_status_code(tiny_http::StatusCode(reponse.code));
    if let Ok(entete) =
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
    {
        http = http.with_header(entete);
    }
    http
}
