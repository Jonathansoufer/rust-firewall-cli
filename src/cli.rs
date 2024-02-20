

pub mod cli {

    use crate::rules::rules::{FIREWALL_RUNNING, RULES, Rule, save_rules};
    use crate::iptables::iptables::{remove_rule, update_iptables};
    use crate::packets::packets::process_packets;
    use crate::logging::logging::view_logs;
    use dialoguer::{theme::ColorfulTheme, Select, Input};
    use pnet::datalink::{self};
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::fs::File;
    use uuid::Uuid;

    fn start_firewall() {
        let interfaces = datalink::interfaces();
        let interface_names: Vec<String> = interfaces.iter()
            .map(|iface| iface.name.clone())
            .collect();
    
        if interface_names.is_empty() {
            println!("No available network interfaces found.");
            return;
        }
    
        // Clean logs when starting the firewall
        clean_logs();
    
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a network interface to monitor")
            .default(0)
            .items(&interface_names)
            .interact()
            .unwrap();
    
        let selected_interface = interface_names.get(selection).unwrap().clone();
        println!("Starting firewall on interface: {}", selected_interface);
    
        FIREWALL_RUNNING.store(true, Ordering::SeqCst);
        thread::spawn(move || {
            process_packets(selected_interface);
        });
    }
    
    fn clean_logs() {
        match File::create("firewall.log") {
            Ok(_) => println!("Logs have been cleaned."),
            Err(e) => eprintln!("Failed to clean logs: {}", e),
        }
    }
    
    fn stop_firewall() {
        FIREWALL_RUNNING.store(false, Ordering::SeqCst);
        println!("Firewall stopped.");
    }
    
    fn check_firewall_status() {
        if FIREWALL_RUNNING.load(Ordering::SeqCst) {
            println!("Firewall status: Running");
        } else {
            println!("Firewall status: Stopped");
        }
    }
    
    pub fn display_menu() {
        let items = vec![
            "View Rules", "Add Rule", "Remove Rule", "View Logs", "Clean Logs",
            "Start Firewall", "Stop Firewall", "Check Firewall Status",
            "Exit"
        ];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an action")
            .default(0)
            .items(&items)
            .interact()
            .unwrap();
    
        match items[selection] {
            "View Rules" => view_rules(),
            "Add Rule" => add_rule(),
            "Remove Rule" => remove_rule(),
            "View Logs" => view_logs(),
            "Clean Logs" => clean_logs(),
            "Start Firewall" => start_firewall(),
            "Stop Firewall" => stop_firewall(),
            "Check Firewall Status" => check_firewall_status(),
            "Exit" => std::process::exit(0),
            _ => (),
        }
    }
    
    fn view_rules() {
        let rules = RULES.lock().unwrap();
        for (index, rule) in rules.iter().enumerate() {
            println!("{}: {:?}", index, rule);
        }
    }
    
    fn add_rule() {
        let protocol: String = Input::new()
            .with_prompt("Enter protocol (e.g., 'tcp', 'udp')")
            .interact_text()
            .unwrap();
    
        let source_ip: String = Input::new()
            .with_prompt("Enter source IP (leave empty if not applicable)")
            .default("".into())
            .interact_text()
            .unwrap();
    
        let destination_ip: String = Input::new()
            .with_prompt("Enter destination IP (leave empty if not applicable)")
            .default("".into())
            .interact_text()
            .unwrap();
    
        let source_port: u16 = Input::new()
            .with_prompt("Enter source port (leave empty if not applicable)")
            .default(0)
            .interact_text()
            .unwrap();
    
        let destination_port: u16 = Input::new()
            .with_prompt("Enter destination port (leave empty if not applicable)")
            .default(0)
            .interact_text()
            .unwrap();
    
        let actions = vec!["Allow", "Block"];
        let action = Select::new()
            .with_prompt("Choose action")
            .default(0)
            .items(&actions)
            .interact()
            .unwrap();
    
        let new_rule = Rule {
            id: Uuid::new_v4().to_string(),
            protocol,
            source_ip: if source_ip.is_empty() { None } else { Some(source_ip) },
            destination_ip: if destination_ip.is_empty() { None } else { Some(destination_ip) },
            source_port: if source_port == 0 { None } else { Some(source_port) },
            destination_port: if destination_port == 0 { None } else { Some(destination_port) },
            action: actions[action].to_lowercase(),
        };
    
        let mut rules = RULES.lock().unwrap();
    
        rules.push(new_rule.clone());
    
        save_rules(&rules).expect("Failed to save rules");
    
        // IMPORTANT: Update Linux IP Tables
        update_iptables(&new_rule.clone(), &new_rule.clone().action);
    
        println!("Rule added.");
    }
}