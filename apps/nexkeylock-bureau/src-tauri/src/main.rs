// Masque la console Windows en release (application graphique).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nexkeylock_bureau_lib::run();
}
