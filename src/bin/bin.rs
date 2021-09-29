extern crate iptables;
extern crate serde;
extern crate serde_yaml;
extern crate regex;
#[macro_use]
extern crate lazy_static;

use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use serde_yaml::from_reader;
use serde::{Serialize, Deserialize};
use std::process::{Command, ExitStatus};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref iptables_regex: Regex = Regex::new(r"-A PREROUTING -s (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) -i (.*?) -p (udp|tcp) --?ma?t?c?h? multiport (!?) --dports (\d{1,5}+)((,\d{1,5})*) -j MARK --set-x?mark 0?x?(\d{1})").unwrap();
}

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



struct IptablesPortRule {
    nic: String,
    source: String,
    protocol: String,
    ports: Vec<u32>,
    not: bool,
    mark: u8
}

impl TryFrom<String> for IptablesPortRule {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let e = iptables_regex.captures(&value).and_then(|capture| Option::from({

            let d: Vec<u32> = capture.get(6).map(|e| e.as_str().split(",").map(|e| e.to_string()).filter(|e| e.len() > 0).map(|e|{e.as_str().parse::<u32>().unwrap()}).collect()).unwrap();
            IptablesPortRule {
                nic: capture.get(2).map(|e| e.as_str()).unwrap().to_string(),
                protocol: capture.get(3).map(|e| e.as_str()).unwrap().to_string(),
                source: capture.get(1).map(|e| e.as_str()).unwrap().to_string(),
                ports: vec!(capture.get(5).map(|e| e.as_str().parse::<u32>().unwrap()).unwrap()).into_iter().chain(d).collect(),
                not: capture.get(4).is_some(),
                mark:  capture.get(8).map(|e| e.as_str().parse::<u8>().unwrap()).unwrap()
            }
        }));

        match e {
             Some(e) => Ok(e),
            None => Err(())
        }
    }
}

impl From<&IptablesPortRule> for String {
    fn from(iptablesRule: &IptablesPortRule) -> Self {
        let source = iptablesRule.source.to_string();
        let nic = iptablesRule.nic.to_string();
        let protocol = iptablesRule.protocol.to_string();
        let dports = iptablesRule.ports.iter().map(|e| e.to_string()).collect::<Vec<String>>().join(",");
        let not = if iptablesRule.not { "!" } else { "" };
        format!("-s {} -i {} -p {} -m multiport {} --dports {} -j MARK --set-mark 1",source, nic, protocol,not, dports)
    }
}

struct Manager<'a> {
    ipt: iptables::IPTables,
    config: &'a Config,
}

impl Manager<'_> {

    fn new(config: &Config) -> Manager {
        Manager {
            ipt: iptables::new(false).unwrap(),
            config,
        }
    }

    fn add_iptables_rule(&self, portRule: &IptablesPortRule) {
        self.ipt.append_unique("mangle", "PREROUTING", String::from(portRule).as_str());
    }

    fn test(&self) {
       // self.ipt.exists()
    }

    fn list_rules(&self) -> Vec<IptablesPortRule> {
        self.ipt.list_table("mangle").unwrap().into_iter().map(|rule| IptablesPortRule::try_from(rule)).filter(|e|e.is_ok()).map(|e| e.unwrap()).collect()
    }

    fn generate_port_rules(&self) -> Vec<IptablesPortRule> {
        todo!()
    }
}

#[derive(Debug,PartialEq)]
enum IpRouteError {
    Error(String)
}

#[derive(Debug,PartialEq)]
enum ParseError {
    Error(String)
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
        println!("meem: {}", d.status);

        assert!(d.status.success());
    }

    fn delete_route(&self, ip: &str, nic: &str, stdRoute: &str) {
        let d = self.get_cmd().arg("route").arg("delete").arg(ip).arg("via").arg(stdRoute).arg("dev").arg(nic).output().unwrap();

        println!("{}", String::from_utf8(d.stderr).unwrap());
        println!("meem: {}", d.status);

        assert!(d.status.success());
    }

    fn check_gateway(&self, nic: &str,gateway: &str) -> Result<(), IpRouteError> {
        let output =  self.get_cmd().arg("route").arg("add").arg("default").arg("via").arg(gateway).arg("dev").arg(nic).output().unwrap();

        let message =  String::from_utf8(output.stderr).unwrap();

        if output.status.success() {
            Ok(())
        } else {
            Err(IpRouteError::Error(message))
        }
    }
}

fn main() {
    println!("Hello, world!");
    let ipt = iptables::new(false).unwrap();
    ipt.flush_table("mangle");
    ipt.append("mangle", "PREROUTING", "-s 0.0.0.0/24 -i eth0 -p udp --match multiport ! --dports 443,1301 -j MARK --set-mark 1").unwrap();
    ipt.list("mangle", "PREROUTING").unwrap().iter().for_each(|e| println!("rule: {}", e));

    let f =  std::fs::File::open("rule_file.yaml").unwrap();
    let config: Config = from_reader(f).unwrap();
    //println!("{:#?}", configs);

    let iproute2 = IpRoute2{};
    let outcome : (Vec<_>,Vec<_>) = config.sinks.iter().map(|sink| iproute2.check_gateway(&sink.nic, &sink.ip)).partition(|r| r.is_err());

    let manager = Manager::new(&config);
    let rules = manager.list_rules();
   // manager.add_iptables_rule(&config.priority_ports.first().unwrap());
    let d = manager.list_rules();
    //println!("{:#?}", d);

    //d.add_route("10.0.0.2", "eth0", "10.0.0.1")

}



