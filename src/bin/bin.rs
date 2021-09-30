extern crate iptables;
extern crate serde;
extern crate serde_yaml;
extern crate regex;
#[macro_use]
extern crate lazy_static;

use std::collections::HashSet;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::num::ParseIntError;
use serde_yaml::from_reader;
use serde::{Serialize, Deserialize};
use std::process::{Command, ExitStatus};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref iptables_regex: Regex = Regex::new(r"-A PREROUTING -s (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) -i (.*?) -p (udp|tcp) --?ma?t?c?h? multiport( ! | )--dports (.*) -j MARK --set-x?mark 0?x?(\d{1})").unwrap();
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Homenet {
    ip: String,
    input_nic: String
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
    ports: String,
    protocol: String
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct IPRule {
    priority: Vec<String>,
    ips: Vec<String>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    homenet: Homenet,
    sinks: Vec<Sink>,
    priority_ports: Vec<PortRule>,
    priority_ip: Vec<IPRule>
}


#[derive(Debug, PartialEq, Eq, Hash)]
struct IptablesPortRule {
    nic: String,
    source: String,
    protocol: String,
    ports: String,
    not: bool,
    mark: u8
}

impl From<ParseIntError> for ParseError {
    fn from(e: ParseIntError) -> Self {
        ParseError::Error(e.to_string())
    }
}

impl TryFrom<String> for IptablesPortRule {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, ParseError> {
        let capture = iptables_regex.captures(&value).ok_or(ParseError::Error("capture not found".to_string()))?;
        let d = IptablesPortRule {
            nic: capture.get(2).map(|e| e.as_str()).ok_or(ParseError::Error("nic not found".to_string()))?.to_string(),
            protocol: capture.get(3).map(|e| e.as_str()).ok_or(ParseError::Error("protocol not found".to_string()))?.to_string(),
            source: capture.get(1).map(|e| e.as_str()).ok_or(ParseError::Error("source not found".to_string()))?.to_string(),
            ports: format!("{}",capture.get(5).map(|e| e.as_str()).ok_or(ParseError::Error("ports not found".to_string()))?),
            not: capture.get(4).map(|e| e.as_str()).ok_or(ParseError::Error("not not found".to_string()))?.to_string().contains("!"),
            mark:  capture.get(6).map(|e| e.as_str().parse::<u8>()).ok_or(ParseError::Error("mark not found".to_string()))??
        };
        Ok(d)
    }
}

impl From<&IptablesPortRule> for String {
    fn from(iptables_rule: &IptablesPortRule) -> Self {
        let source = iptables_rule.source.to_string();
        let nic = iptables_rule.nic.to_string();
        let protocol = iptables_rule.protocol.to_string();
        let dports = iptables_rule.ports.clone();
        let not = if iptables_rule.not { "!" } else { "" };
        format!("-s {} -i {} -p {} -m multiport {} --dports {} -j MARK --set-mark 1",source, nic, protocol,not, dports)
    }
}

impl From<(&PortRule,&Homenet)> for IptablesPortRule {
    fn from((rule,homenet): (&PortRule, &Homenet)) -> Self {
        IptablesPortRule {
            nic: homenet.input_nic.to_string(),
            mark: 1,
            not: rule.not,
            source: homenet.ip.to_string(),
            protocol: rule.protocol.to_string(),
            ports: rule.ports.clone()
        }
    }
}

struct Manager<'a> {
    ipt: iptables::IPTables,
    config: &'a Config,
}

struct IpTablesRuleDiff<'a> {
    added: Vec<&'a IptablesPortRule>,
    deleted: Vec<&'a IptablesPortRule>,
    same: Vec<&'a IptablesPortRule>
}

impl Manager<'_> {

    fn new(config: &Config) -> Manager {
        Manager {
            ipt: iptables::new(false).unwrap(),
            config,
        }
    }

    fn add_iptables_rule(&self, port_rule: &IptablesPortRule) {
        self.ipt.append_unique("mangle", "PREROUTING", String::from(port_rule).as_str()).unwrap();
    }

    fn delete_iptables_rule(&self, port_rule: &IptablesPortRule) {
        self.ipt.delete("mangle", "PREROUTING", String::from(port_rule).as_str()).unwrap();
    }

    fn delete_all(&self) {
        self.ipt.flush_table("mangle");
    }

    fn test(&self) {
       // self.ipt.exists()
    }

    fn list_rules(&self) -> HashSet<IptablesPortRule> {
        self.ipt.list_table("mangle").unwrap().into_iter().map(|rule| IptablesPortRule::try_from(rule)).filter(|e| e.is_ok()).map(|e| e.unwrap()).collect()
    }

    fn insert_rules(&self) {
        self.config.priority_ports.iter().for_each(|r| {
            let d:IptablesPortRule = (r,&self.config.homenet).into();
            self.add_iptables_rule(&d);
        })
    }

    fn get_altered_rules<'a>(&self, existing_rules: &'a HashSet<IptablesPortRule>, rules_from_config: &'a HashSet<IptablesPortRule>) -> IpTablesRuleDiff<'a> {
        let to_delete = existing_rules.difference(&rules_from_config).collect();
        let to_add = rules_from_config.difference(&existing_rules).collect();
        let same = rules_from_config.intersection(&existing_rules).collect();

        IpTablesRuleDiff {
            added: to_add,
            deleted: to_delete,
            same
        }
    }

    fn sync(&self, diff: &IpTablesRuleDiff) {
        println!("Add {} rules and delete {}. {} Are the same.", diff.added.len(), diff.deleted.len(), diff.same.len());
        diff.added.iter().for_each(|r| self.add_iptables_rule(r));
        diff.deleted.iter().for_each(|r| self.delete_iptables_rule(r));
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

    fn add_route(&self, ip: &str, nic: &str, std_route: &str) {
        let d = self.get_cmd().arg("route").arg("add").arg(ip).arg("via").arg(std_route).arg("dev").arg(nic).output().unwrap();
        println!("{}", String::from_utf8(d.stderr).unwrap());
        println!("meem: {}", d.status);

        assert!(d.status.success());
    }

    fn delete_route(&self, ip: &str, nic: &str, std_route: &str) {
        let d = self.get_cmd().arg("route").arg("delete").arg(ip).arg("via").arg(std_route).arg("dev").arg(nic).output().unwrap();

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

    let f =  std::fs::File::open("rule_file.yaml").unwrap();
    let config: Config = from_reader(f).unwrap();
    //println!("{:#?}", configs);

    let iproute2 = IpRoute2{};
    let outcome : (Vec<_>,Vec<_>) = config.sinks.iter().map(|sink| iproute2.check_gateway(&sink.nic, &sink.ip)).partition(|r| r.is_err());

    let manager = Manager::new(&config);

    let existing_rules: HashSet<IptablesPortRule> = manager.list_rules();
    let rules_from_config: HashSet<IptablesPortRule> = manager.config.priority_ports.iter().map(|p| (p,&manager.config.homenet).into()).collect();
    let overview = manager.get_altered_rules(&existing_rules, &rules_from_config);

    let rules = manager.list_rules();
    manager.sync(&overview);
   // manager.add_iptables_rule(&config.priority_ports.first().unwrap());
    rules.iter().for_each(|e|println!("{:#?}",e))


    //d.add_route("10.0.0.2", "eth0", "10.0.0.1")

}



