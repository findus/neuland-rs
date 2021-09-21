extern crate iptables;
extern crate serde;
extern crate serde_yaml;

use serde_yaml::from_reader;
use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Sink {
    name: String,
    ip: String,
    nic: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PortRule {
    not: bool,
    length: Option<String>,
    ports: Vec<String>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct IPRule {
    priority: Vec<String>,
    ips: Vec<String>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    homenet: String,
    sinks: Vec<Sink>,
    priority_ports: Vec<PortRule>,
    priority_ip: Vec<IPRule>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Rule {
    nic: String,
    chain: String,
    table: String,
    source: String,
    protocol: String,
    rule: String
}

fn main() {
    println!("Hello, world!");
    let ipt = iptables::new(false).unwrap();
    ipt.append("mangle", "PREROUTING", "-s 0.0.0.0/24  -i eth0 -p udp --match multiport ! --dports 443,1301 --j MARK --set-mark 1").unwrap();
    ipt.list("mangle", "PREROUTING").unwrap().iter().for_each(|e| println!("{}", e));

    let f =  std::fs::File::open("rule_file.yaml").unwrap();
    let d: Config = from_reader(f).unwrap();
    println!("{:#?}", d);

}

