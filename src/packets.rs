pub mod packets {

    use pnet::datalink::Channel::Ethernet;
    use pnet::datalink::{self};
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::Packet;
    use crate::rules::rules::{Rule, RULES,FIREWALL_RUNNING};
    use crate::logging::logging::log_packet_action;
    use std::sync::atomic::Ordering;


    pub fn process_packets(interface_name: String) {
        let interfaces = datalink::interfaces();
        let interface = interfaces.into_iter()
            .find(|iface| iface.name == interface_name)
            .expect("Error finding interface");
    
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(_, rx)) => ((), rx),
            Ok(_) => panic!("Unsupported channel type"),
            Err(e) => panic!("Error creating datalink channel: {}", e),
        };
    
        while FIREWALL_RUNNING.load(Ordering::SeqCst) {
            match rx.next() {
                Ok(packet) => {
                    if let Some(tcp_packet) = TcpPacket::new(packet) {
                        process_tcp_packet(&tcp_packet);
                    }
                },
                Err(e) => eprintln!("An error occurred while reading packet: {}", e),
            }
        }
    }
    
    fn process_tcp_packet(tcp_packet: &TcpPacket) {
    
        let rules = RULES.lock().unwrap();
        for rule in rules.iter() {
            if packet_matches_rule(tcp_packet, rule) {
                println!("Rule matched");
                match rule.action.as_str() {
                    "block" => {
                        log_packet_action(tcp_packet, "Blocked");
                        return; // Dropping the packet
                    },
                    _ => (),
                }
            }
        }
    
        log_packet_action(tcp_packet, "Allowed");
        // Further processing or forwarding the packet
    }
    
    fn packet_matches_rule(packet: &TcpPacket, rule: &Rule) -> bool {
        // First, extract the IPv4 packet from the TCP packet
        if let Some(ipv4_packet) = Ipv4Packet::new(packet.packet()) {
    
            // Check protocol (assuming TCP, as we are working with TcpPacket)
            if rule.protocol.to_lowercase() != "tcp" {
                return false;
            }
    
            // Check source IP
            if let Some(ref rule_src_ip) = rule.source_ip {
                if ipv4_packet.get_source().to_string() != *rule_src_ip {
                    return false;
                }
            }
    
            // Check destination IP
            if let Some(ref rule_dst_ip) = rule.destination_ip {
                if ipv4_packet.get_destination().to_string() != *rule_dst_ip {
                    return false;
                }
            }
    
            // Check source port
            if let Some(rule_src_port) = rule.source_port {
                if packet.get_source() != rule_src_port {
                    return false;
                }
            }
    
            // Check destination port
            if let Some(rule_dst_port) = rule.destination_port {
                if packet.get_destination() != rule_dst_port {
                    return false;
                }
            }
    
            // If all checks pass, the packet matches the rule
            return true;
        }
    
        false
    }
}