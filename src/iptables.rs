pub mod iptables {

use dialoguer::{theme::ColorfulTheme, Select};
use std::process::{Command, Stdio};
use crate::rules::rules::{Rule,RULES};

    pub fn update_iptables(rule: &Rule, action: &str) {
        let protocol = &rule.protocol;
        let source_ip = rule.source_ip.as_ref().map_or("".to_string(), |ip| format!("--source {}", ip));
        let destination_ip = rule.destination_ip.as_ref().map_or("".to_string(), |ip| format!("--destination {}", ip));
        let source_port = rule.source_port.map_or("".to_string(), |port| format!("--sport {}", port));
        let destination_port = rule.destination_port.map_or("".to_string(), |port| format!("--dport {}", port));
        let target = if action == "block" { "DROP" } else { "ACCEPT" };
    
        // Construct the iptables command as a string
        let iptables_command = format!("sudo iptables -A INPUT -p {} {} {} {} {} -j {} -m comment --comment {}",
        protocol, source_ip, destination_ip, source_port, destination_port, target, &rule.id);
    
        // Print the executed command for debugging purposes
        println!("Executing command: {}", iptables_command);
    
        // Execute the iptables command
        let output = Command::new("sh")
            .arg("-c")
            .arg(&iptables_command)
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to execute iptables command");
    
        if output.status.success() {
            println!("Rule updated in iptables.");
        } else {
            // Print the raw error message from stderr
            let stderr_output = String::from_utf8_lossy(&output.stderr);
            eprintln!("Failed to update rule in iptables. Error: {}", stderr_output);
        }
    }
    
    pub fn remove_rule() {
        // Get the rule descriptions and selection
        let (selected_rule_id, selection) = {
            let rules = RULES.lock().unwrap();
            let rule_descriptions: Vec<String> = rules.iter().map(|rule| format!("{:?}", rule)).collect();
    
            if rule_descriptions.is_empty() {
                println!("No rules to remove.");
                return;
            }
    
            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Select a rule to remove")
                .default(0)
                .items(&rule_descriptions)
                .interact()
                .unwrap();
    
            // Clone the ID to use outside the lock scope
            let selected_rule_id = rules[selection].id.clone();
            (selected_rule_id, selection)
        };
    
        // Now we can remove the iptables rule outside the lock scope
        remove_iptables_rule(&selected_rule_id);
    
        // Now remove the rule from the application
        let mut rules = RULES.lock().unwrap();
    
        rules.remove(selection);
    
        println!("Rule removed.");
    }
    
    
    fn remove_iptables_rule(rule_id: &str) {
        // Construct the iptables command as a string
        let iptables_command = format!(
            "sudo iptables -L INPUT --line-numbers | grep -E '{}' | awk '{{print $1}}' | xargs -I {{}} sudo iptables -D INPUT {{}}",
            rule_id
        );
    
        // Print the executed command for debugging purposes
        println!("Executing command: {}", iptables_command);
    
        // Execute the iptables command
        let output = Command::new("sh")
            .arg("-c")
            .arg(&iptables_command)
            .output()
            .expect("Failed to execute iptables command");
    
        // Print the output of the executed command for debugging
        println!("Command output: {:?}", output);
    
        if output.status.success() {
            println!("Successfully removed iptables rule for rule ID: {}", rule_id);
        } else {
            eprintln!("Error removing iptables rule for rule ID: {}", rule_id);
        }
    }
}
