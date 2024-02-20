pub mod rules {

use lazy_static::lazy_static;
use std::io::Read;
use std::{fs, io};
use std::path::Path;
use std::fs::File;
use serde_derive::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub protocol: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub action: String, // "allow" or "block"
}

lazy_static! {
    pub static ref RULES: Arc<Mutex<Vec<Rule>>> = Arc::new(Mutex::new(Vec::new()));
}

lazy_static! {
    pub static ref FIREWALL_RUNNING: AtomicBool = AtomicBool::new(false);
}

const RULES_FILE: &str = "firewall_rules.json";

pub fn save_rules(rules: &Vec<Rule>) -> io::Result<()> {
    let json = serde_json::to_string(rules)?;
    fs::write(RULES_FILE, json)?;
    Ok(())
}

pub fn load_rules() -> io::Result<Vec<Rule>> {
    let path = Path::new(RULES_FILE);
    if path.exists() {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let rules = serde_json::from_str(&contents)?;
        Ok(rules)
    } else {
        Ok(Vec::new())
    }
}
}