//! Interface en ligne de commande de nexkeylock.
//!
//! Au Jalon 4, ce binaire exposera les commandes : `init`, `unlock`, `add`,
//! `get`, `list`, `edit`, `rm`, `generate`, `audit`, `totp`, `export`,
//! `import`, `change-password`. Pour l'instant (Jalon 0), il s'agit d'un
//! squelette qui confirme uniquement que le workspace compile et s'exécute.

fn main() {
    println!(
        "nexkeylock {} — squelette du Jalon 0 (l'interface arrive au Jalon 4).",
        env!("CARGO_PKG_VERSION")
    );
}
