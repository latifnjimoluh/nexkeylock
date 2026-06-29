//! Dérivation de clé par **Argon2id** (RFC 9106).
//!
//! Le mot de passe maître n'est **jamais** utilisé directement comme clé : il
//! est transformé par cette fonction mémoire-dure, qui rend la force brute
//! hors-ligne prohibitivement coûteuse. Les paramètres (`m`, `t`, `p`) sont
//! destinés à être stockés dans l'en-tête du coffre (agilité cryptographique).
//!
//! Paramètres par défaut (production) : `m = 256 Mio`, `t = 3`, `p = 4`,
//! sortie 32 octets — à calibrer à ~0,5 s sur le matériel cible par benchmark.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::erreurs::ErreurCrypto;
use crate::secret::{CleSecrete, LONGUEUR_CLE};

/// Mémoire par défaut, en Kio (256 Mio).
pub const MEMOIRE_KIO_DEFAUT: u32 = 262_144;
/// Nombre d'itérations (passes) par défaut.
pub const ITERATIONS_DEFAUT: u32 = 3;
/// Degré de parallelisme par défaut.
pub const PARALLELISME_DEFAUT: u32 = 4;

/// Paramètres de coût d'Argon2id, stockés en clair dans l'en-tête du coffre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParametresArgon2 {
    /// Mémoire utilisée, en Kio.
    pub memoire_kio: u32,
    /// Nombre d'itérations (passes).
    pub iterations: u32,
    /// Degré de parallelisme.
    pub parallelisme: u32,
}

impl Default for ParametresArgon2 {
    fn default() -> Self {
        Self {
            memoire_kio: MEMOIRE_KIO_DEFAUT,
            iterations: ITERATIONS_DEFAUT,
            parallelisme: PARALLELISME_DEFAUT,
        }
    }
}

impl ParametresArgon2 {
    /// Construit un jeu de paramètres explicite.
    pub fn new(memoire_kio: u32, iterations: u32, parallelisme: u32) -> Self {
        Self {
            memoire_kio,
            iterations,
            parallelisme,
        }
    }

    /// Convertit en [`Params`] de la crate `argon2`, sortie fixée à 32 octets.
    ///
    /// # Erreurs
    /// Renvoie [`ErreurCrypto::ParametresKdf`] si les paramètres sont invalides.
    fn en_params(self) -> Result<Params, ErreurCrypto> {
        Params::new(
            self.memoire_kio,
            self.iterations,
            self.parallelisme,
            Some(LONGUEUR_CLE),
        )
        .map_err(|_| ErreurCrypto::ParametresKdf)
    }
}

/// Dérive une clé de 256 bits à partir d'un mot de passe et d'un sel.
///
/// Le sel doit faire au moins 16 octets, être généré par CSPRNG et unique par
/// coffre (validation de longueur déléguée à `argon2`).
///
/// # Erreurs
/// - [`ErreurCrypto::ParametresKdf`] si les paramètres sont invalides ;
/// - [`ErreurCrypto::DerivationKdf`] si la dérivation échoue (p. ex. sel trop
///   court).
pub fn deriver_cle(
    mot_de_passe: &[u8],
    sel: &[u8],
    parametres: ParametresArgon2,
) -> Result<CleSecrete, ErreurCrypto> {
    deriver_cle_avec_secret(mot_de_passe, sel, parametres, &[])
}

/// Dérive une clé en mélangeant un **secret** supplémentaire (paramètre « secret »
/// d'Argon2id, RFC 9106) : c'est le mécanisme du **fichier-clé** (second facteur).
///
/// Un `secret` **vide** est strictement équivalent à [`deriver_cle`] : la
/// compatibilité avec les coffres existants (sans fichier-clé) est donc totale.
/// Avec un fichier-clé, la clé ne peut être recalculée **sans** ce secret —
/// même en connaissant le mot de passe.
///
/// # Erreurs
/// - [`ErreurCrypto::ParametresKdf`] si les paramètres ou le secret sont invalides ;
/// - [`ErreurCrypto::DerivationKdf`] si la dérivation échoue.
pub fn deriver_cle_avec_secret(
    mot_de_passe: &[u8],
    sel: &[u8],
    parametres: ParametresArgon2,
    secret: &[u8],
) -> Result<CleSecrete, ErreurCrypto> {
    let argon = Argon2::new_with_secret(
        secret,
        Algorithm::Argon2id,
        Version::V0x13,
        parametres.en_params()?,
    )
    .map_err(|_| ErreurCrypto::ParametresKdf)?;
    let mut sortie = [0u8; LONGUEUR_CLE];
    argon
        .hash_password_into(mot_de_passe, sel, &mut sortie)
        .map_err(|_| ErreurCrypto::DerivationKdf)?;
    let cle = CleSecrete::depuis_octets(sortie);
    sortie.zeroize();
    Ok(cle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Paramètres légers réservés aux tests (rapides). Les vecteurs officiels
    // (RFC 9106) utilisent, eux, les paramètres exacts de la RFC.
    fn params_test() -> ParametresArgon2 {
        ParametresArgon2::new(8, 1, 1)
    }

    #[test]
    fn determinisme_memes_entrees() {
        let sel = [0x42u8; 16];
        let a = deriver_cle(b"motdepasse", &sel, params_test()).unwrap();
        let b = deriver_cle(b"motdepasse", &sel, params_test()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sel_different_donne_cle_differente() {
        let a = deriver_cle(b"motdepasse", &[0x01u8; 16], params_test()).unwrap();
        let b = deriver_cle(b"motdepasse", &[0x02u8; 16], params_test()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn mot_de_passe_different_donne_cle_differente() {
        let sel = [0x42u8; 16];
        let a = deriver_cle(b"motdepasse-a", &sel, params_test()).unwrap();
        let b = deriver_cle(b"motdepasse-b", &sel, params_test()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_vide_equivaut_a_sans_secret() {
        // Compatibilité ascendante : un fichier-clé vide ne change rien.
        let sel = [0x42u8; 16];
        let sans = deriver_cle(b"motdepasse", &sel, params_test()).unwrap();
        let avec_vide = deriver_cle_avec_secret(b"motdepasse", &sel, params_test(), &[]).unwrap();
        assert_eq!(sans, avec_vide);
    }

    #[test]
    fn secret_different_donne_cle_differente() {
        // Même mot de passe + même sel, mais fichiers-clés différents => clés différentes.
        let sel = [0x42u8; 16];
        let a = deriver_cle_avec_secret(b"motdepasse", &sel, params_test(), &[0x01; 32]).unwrap();
        let b = deriver_cle_avec_secret(b"motdepasse", &sel, params_test(), &[0x02; 32]).unwrap();
        let sans = deriver_cle(b"motdepasse", &sel, params_test()).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, sans);
    }

    #[test]
    fn meme_secret_donne_meme_cle() {
        let sel = [0x42u8; 16];
        let a = deriver_cle_avec_secret(b"mdp", &sel, params_test(), &[0x07; 32]).unwrap();
        let b = deriver_cle_avec_secret(b"mdp", &sel, params_test(), &[0x07; 32]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sel_trop_court_echoue_proprement() {
        // Argon2 exige un sel d'au moins 8 octets : échec typé, pas de panic.
        let erreur = deriver_cle(b"motdepasse", &[0u8; 4], params_test()).unwrap_err();
        assert!(matches!(erreur, ErreurCrypto::DerivationKdf));
    }

    /// Vecteur officiel Argon2id de la RFC 9106 (avec clé secrète et données
    /// associées). On exerce ici la primitive de bas niveau de la crate `argon2`
    /// car ce vecteur utilise les paramètres « secret » et « data » que
    /// `deriver_cle` n'expose pas. Un seul octet d'écart = implémentation fausse.
    #[test]
    fn vecteur_officiel_rfc9106() {
        use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

        let mot_de_passe = [0x01u8; 32];
        let sel = [0x02u8; 16];
        let secret = [0x03u8; 8];

        let parametres = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[0x04u8; 12]).unwrap())
            .build()
            .unwrap();
        let contexte =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, parametres)
                .unwrap();

        let mut sortie = [0u8; 32];
        contexte
            .hash_password_into(&mot_de_passe, &sel, &mut sortie)
            .unwrap();

        // Sortie de référence de la RFC 9106, §5.3 (Argon2id, v=0x13).
        let attendu =
            hex_literal::hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
        assert_eq!(sortie, attendu);
    }
}
