extern crate iptables;
extern crate serde;
extern crate serde_yaml;

use serde_yaml::from_reader;
use serde::{Serialize, Deserialize};
use std::process::{Command, ExitStatus};

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

struct Manager<'a> {
    ipt: iptables::IPTables,
    config: &'a Config
}

impl Manager<'_> {

    fn new(config: &Config) -> Manager {
        Manager {
            ipt: iptables::new(false).unwrap(),
            config
        }
    }

    fn add_iptables_rule(&self, portRule: &PortRule) {
        self.ipt.append_unique("mangle", "PREROUTING", "");
    }

    fn test(&self) {
       // self.ipt.exists()
    }
}

struct IpRoute2 {

}

impl IpRoute2 {

    fn get_cmd(&self) -> Command {
        Command::new("ip")
    }

    fn add_route(&self, ip: &str, nic: &str, stdRoute: &str) {
        let d = self.get_cmd().arg("route").arg("add").arg(ip).arg("via").arg(stdRoute).arg("dev").arg(nic).output().unwrap();
        println!("{}", String::from_utf8(d.stderr).unwrap());
        assert!(d.status.success());
    }

    fn delete_route(&self, ip: &str, nic: &str, stdRoute: &str) {
        let d = self.get_cmd().arg("route").arg("delete").arg(ip).arg("via").arg(stdRoute).arg("dev").arg(nic).output().unwrap();
        println!("{}", String::from_utf8(d.stderr).unwrap());
        assert!(d.status.success());
    }
}

fn main() {
    println!("Hello, world!");
    let ipt = iptables::new(false).unwrap();
    ipt.append("mangle", "PREROUTING", "-s 0.0.0.0/24  -i eth0 -p udp --match multiport ! --dports 443,1301 --j MARK --set-mark 1").unwrap();
    ipt.list("mangle", "PREROUTING").unwrap().iter().for_each(|e| println!("{}", e));

    let f =  std::fs::File::open("rule_file.yaml").unwrap();
    let d: Config = from_reader(f).unwrap();
    println!("{:#?}", d);

    let manager = Manager::new(&d);
    manager.add_iptables_rule(&d.priority_ports.first().unwrap());
    let d = IpRoute2{};
    d.add_route("10.0.0.2", "eth0", "10.0.0.1")

}



