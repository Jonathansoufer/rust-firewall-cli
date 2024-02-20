pub mod logging {
    use pnet::packet::tcp::TcpPacket;
    use std::fs::{self, OpenOptions};
    use std::io::Write;

pub fn log_packet_action(packet: &TcpPacket, action: &str) {
    let log_message = format!("{} packet: {:?}, action: {}\n", action, packet, action);
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("firewall.log")
        .unwrap();

    if let Err(e) = writeln!(file, "{}", log_message) {
        eprintln!("Couldn't write to log file: {}", e);
    }
}

pub fn view_logs() {
    println!("Firewall Logs:");
    match fs::read_to_string("firewall.log") {
        Ok(contents) => println!("{}", contents),
        Err(e) => println!("Error reading log file: {}", e),
    }
}
}

