//! Durcissement du processus au démarrage.
//!
//! Vise à réduire la surface d'exposition des secrets en mémoire. Le
//! verrouillage des pages de clés (`VirtualLock`/`mlock`) est assuré au niveau
//! des secrets eux-mêmes (cf. `nex_cryptographie::secret::CleSecrete`). Ce module
//! traite le durcissement **global au processus** : la désactivation des
//! vidages mémoire (*core dumps*).
//!
//! Garanties **honnêtes** :
//! - Sous **Unix**, `RLIMIT_CORE` est fixé à 0 : le noyau n'écrit pas de vidage
//!   du processus en cas de plantage.
//! - Sous **Windows**, les vidages utilisateur relèvent de *Windows Error
//!   Reporting* (politique système) et **ne peuvent pas** être désactivés de
//!   façon fiable par l'application : non-opération documentée.

/// Désactive les vidages mémoire (*core dumps*) du processus, best-effort.
///
/// Un échec éventuel est volontairement ignoré (durcissement « au mieux »).
#[cfg(unix)]
pub fn desactiver_core_dumps() {
    let limite = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY : appel POSIX `setrlimit` avec une structure `rlimit` entièrement
    // initialisée, passée par pointeur const valide pour la durée de l'appel.
    // Aucun invariant Rust n'est mis en jeu ; le code de retour est ignoré
    // (durcissement best-effort). Unique bloc `unsafe` du crate, audité.
    #[allow(unsafe_code)]
    unsafe {
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &limite);
    }
}

/// Variante non-Unix : non-opération (cf. limites documentées ci-dessus).
#[cfg(not(unix))]
pub fn desactiver_core_dumps() {}

#[cfg(test)]
mod tests {
    #[test]
    fn desactivation_ne_panique_pas() {
        super::desactiver_core_dumps();
    }

    #[cfg(unix)]
    #[test]
    fn core_dumps_a_zero_sous_unix() {
        super::desactiver_core_dumps();
        // SAFETY : lecture de la limite via `getrlimit` dans une structure
        // locale entièrement initialisée à zéro.
        #[allow(unsafe_code)]
        let lu = unsafe {
            let mut l: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut l), 0);
            l
        };
        assert_eq!(lu.rlim_cur, 0);
    }
}
