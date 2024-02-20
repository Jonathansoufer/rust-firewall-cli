
use crate::rules::rules::RULES;
use crate::rules::rules::load_rules;
use crate::cli::cli::display_menu;

pub mod cli;
pub mod rules;
pub mod packets;
pub mod logging;
pub mod iptables;

fn main() {
    let loaded_rules = load_rules().unwrap_or_else(|e| {
        eprintln!("Failed to load rules: {}", e);
        Vec::new()
    });

    *RULES.lock().unwrap() = loaded_rules;

    loop {
        display_menu();
    }
}