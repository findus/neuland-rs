extern crate iptables;
extern crate serde;
extern crate serde_yaml;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate env_logger;
extern crate colored;

use std::collections::{HashSet, HashMap};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::num::ParseIntError;
use serde_yaml::from_reader;
use serde::{Serialize, Deserialize};
use std::process::{Command, ExitStatus};
use std::thread::sleep;
use std::time::Duration;
use itertools::Itertools;
use regex::Regex;
use lazy_static::lazy_static;
use colored::Colorize;

lazy_static! {
    static ref iptables_regex: Regex = Regex::new(r"-A PREROUTING -s (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) -i (.*?) -p (udp|tcp) --?ma?t?c?h? multiport( ! | )--dports (.*) -j MARK --set-x?mark 0?x?(\d{1})").unwrap();
    static ref route_dev_regex: Regex = Regex::new(r"dev ([^ \n]+)").unwrap();
    static ref route_gateway_regex: Regex = Regex::new(r"via ([^ \n]+)").unwrap();
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
    ips: Vec<String>,
    name: String
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    homenet: Homenet,
    sinks: Vec<Sink>,
    priority_ports: Vec<PortRule>,
    priority_ip: Vec<IPRule>
}


#[derive(Debug, PartialEq, Eq, Hash)]
struct InternalIptablesPortRule {
    nic: String,
    source: String,
    protocol: String,
    ports: String,
    not: bool,
    mark: u8
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct InternalIpRule {
    nic: String,
    ip: String,
    gateway: Option<String>
}

impl From<ParseIntError> for ParseError {
    fn from(e: ParseIntError) -> Self {
        ParseError::Error(e.to_string())
    }
}

impl TryFrom<String> for InternalIpRule {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let dev_capture = route_dev_regex.captures(&value).ok_or(ParseError::Error("device_capture not found".to_string()))?;
        let gw_capture = route_gateway_regex.captures(&value);

        let ip = value.split(" ").into_iter().nth(0).unwrap().to_string();
        let device = dev_capture.get(1).map(|e| e.as_str()).ok_or(ParseError::Error("device not found".to_string()))?.to_string();
        let gateway =  gw_capture.and_then(|c| c.get(1).map(|e| e.as_str()));

        Ok(InternalIpRule {
            nic: device,
            ip,
            gateway: gateway.map(|e| e.to_string())
        })
    }
}

impl TryFrom<String> for InternalIptablesPortRule {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, ParseError> {
        let capture = iptables_regex.captures(&value).ok_or(ParseError::Error("capture not found".to_string()))?;
        let d = InternalIptablesPortRule {
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

impl From<&InternalIpRule> for String {
    fn from(rule: &InternalIpRule) -> Self {
        if rule.gateway.is_some() {
            format!("{} via {} dev {}", rule.ip, rule.gateway.as_ref().unwrap(), rule.nic)
        } else {
            format!("{} dev {}", rule.ip, rule.nic)
        }
    }
}

impl From<&InternalIptablesPortRule> for String {
    fn from(iptables_rule: &InternalIptablesPortRule) -> Self {
        let source = iptables_rule.source.to_string();
        let nic = iptables_rule.nic.to_string();
        let protocol = iptables_rule.protocol.to_string();
        let dports = iptables_rule.ports.clone();
        let not = if iptables_rule.not { "!" } else { "" };
        format!("-s {} -i {} -p {} -m multiport {} --dports {} -j MARK --set-mark 1",source, nic, protocol,not, dports)
    }
}

impl From<(&PortRule,&Homenet)> for InternalIptablesPortRule {
    fn from((rule,homenet): (&PortRule, &Homenet)) -> Self {
        InternalIptablesPortRule {
            nic: homenet.input_nic.to_string(),
            mark: 1,
            not: rule.not,
            source: homenet.ip.to_string(),
            protocol: rule.protocol.to_string(),
            ports: rule.ports.clone()
        }
    }
}

struct IPTablesManager<'a> {
    ipt: iptables::IPTables,
    config: &'a Config,
}

struct IpTablesRuleDiff<'a> {
    added: Vec<&'a InternalIptablesPortRule>,
    deleted: Vec<&'a InternalIptablesPortRule>,
    same: Vec<&'a InternalIptablesPortRule>
}

struct IpRuleDiff<'a> {
    added: Vec<&'a InternalIpRule>,
    deleted: Vec<&'a InternalIpRule>,
    same: Vec<&'a InternalIpRule>
}

impl IPTablesManager<'_> {

    fn new(config: &Config) -> IPTablesManager {
        IPTablesManager {
            ipt: iptables::new(false).unwrap(),
            config,
        }
    }

    fn add_iptables_rule(&self, port_rule: &InternalIptablesPortRule) {
        self.ipt.append_unique("mangle", "PREROUTING", String::from(port_rule).as_str()).unwrap();
    }

    fn delete_iptables_rule(&self, port_rule: &InternalIptablesPortRule) {
        self.ipt.delete("mangle", "PREROUTING", String::from(port_rule).as_str()).unwrap();
    }

    fn delete_all(&self) {
        self.ipt.flush_table("mangle");
    }

    fn list_rules(&self) -> HashSet<InternalIptablesPortRule> {
        self.ipt.list_table("mangle").unwrap()
            .into_iter()
            .map(|rule| InternalIptablesPortRule::try_from(rule))
            .filter(|e| e.is_ok())
            .map(|e| e.unwrap())
            .collect()
    }

    fn insert_rules(&self) {
        self.config.priority_ports.iter().for_each(|r| {
            let d: InternalIptablesPortRule = (r, &self.config.homenet).into();
            self.add_iptables_rule(&d);
        })
    }

    fn get_rule_diff<'a>(&self, existing_rules: &'a HashSet<InternalIptablesPortRule>, rules_from_config: &'a HashSet<InternalIptablesPortRule>) -> IpTablesRuleDiff<'a> {
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

struct IpRoute2<'a> {
    config: &'a Config,
}

impl IpRoute2<'_> {

    fn get_active_sinks<'a>(&'a self) -> HashMap<String, Vec<&'a Sink>> {
        self.config.sinks
            .iter()
            .filter( |sink| String::from_utf8(self.get_cmd().args(&["link", "show", &sink.nic]).output().unwrap().stdout).unwrap().contains("state"))
            .into_group_map_by(|e| e.name.to_string())
    }


    fn get_cmd(&self) -> Command {
        Command::new("ip")
    }

    fn calc_internal_rules_from_config(&self) -> HashSet<InternalIpRule> {
        let sinks = self.get_active_sinks();

        self.config.priority_ip.iter().map(|rule| {
            let first_available_sink = rule.priority.iter().filter(|pr| sinks.contains_key(&*pr.to_string())).nth(0).unwrap();
            let sink = sinks.get(first_available_sink).unwrap().first().unwrap();
            log::info!("Sink for {}: {}", rule.name, sink.name);
            rule.ips.iter().map(|r| {
                InternalIpRule {
                    nic: (&sink.nic).to_string(),
                    ip: (r).to_string(),
                    gateway: Some((&sink.ip).to_string()),
                }
            }).collect::<HashSet<_>>()
        }).flatten().collect()
    }

    fn list_routes(&self) -> HashSet<InternalIpRule> {
        let stdout = self.get_cmd().arg("route").output().unwrap().stdout;
        if stdout.len() == 0 {
            return HashSet::new();
        }
        String::from_utf8_lossy(stdout.as_slice())
            .trim()
            .split('\n')
            .map(String::from)
            .map(|str| InternalIpRule::try_from(str).unwrap())
            //dont delete nexthop
            .filter(|rule| rule.ip.eq(&self.config.homenet.ip) == false)
            .collect()
    }

    fn get_route_diff<'a>(&self, rules_from_config: &'a HashSet<InternalIpRule>, existing_rules: &'a HashSet<InternalIpRule>) -> IpRuleDiff<'a> {
        let to_delete = existing_rules.difference(&rules_from_config).collect();
        let to_add = rules_from_config.difference(&existing_rules).collect();
        let same = rules_from_config.intersection(&existing_rules).collect();

        IpRuleDiff {
            added: to_add,
            deleted: to_delete,
            same
        }
    }

    fn add_route(&self, rule: &InternalIpRule) {
        let mut cmd = self.get_cmd();
        let e = (&mut cmd).arg("route").arg("add").args(String::from(rule).split(" "));
        log::debug!("{:#?}",e);
        let o = e.output().unwrap().stderr;
        print_output(o);
    }

    fn delete_route(&self, rule: &InternalIpRule) {
        let mut cmd = self.get_cmd();
        let e = (&mut cmd).arg("route").arg("delete").args(String::from(rule).split(" "));
        log::debug!("{:#?}",e);
        let o = e.output().unwrap().stderr;
        print_output(o);
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

fn print_output(output: Vec<u8>) {
    String::from_utf8_lossy( output.as_slice())
        .trim()
        .split('\n')
        .map(String::from)
        .for_each(|e| {
            log::debug!("{}",e.red());
        });
}

fn main() {
    env_logger::init();
    String::from_utf8_lossy(Command::new("whoami").output().unwrap().stdout.as_slice())
        .trim()
        .split('\n')
        .map(String::from)
        .for_each(|e|     println!("I am {}",e ));

    let f =  std::fs::File::open("rule_file.yaml").unwrap();
    let config: Config = from_reader(f).unwrap();

    let iproute2 = IpRoute2{ config: &config };

    let b = iproute2.calc_internal_rules_from_config();
    let active = &iproute2.list_routes();
    let a = iproute2.get_route_diff(&b, &active);

    log::info!("Will add {} and delete {} IP Rules .. {} are the same.", a.added.len().to_string().green(), a.deleted.len().to_string().red(), a.same.len().to_string().white());


    a.deleted.iter().for_each(|c| {
        iproute2.delete_route(c);
    });

    a.added.iter().for_each(|c| {
        iproute2.add_route(c);
    });

    let outcome : (Vec<_>,Vec<_>) = config.sinks.iter().map(|sink| iproute2.check_gateway(&sink.nic, &sink.ip)).partition(|r| r.is_err());

    let manager = IPTablesManager::new(&config);

    let existing_rules: HashSet<InternalIptablesPortRule> = manager.list_rules();
    let rules_from_config: HashSet<InternalIptablesPortRule> = manager.config.priority_ports.iter().map(|p| (p, &manager.config.homenet).into()).collect();
    let overview = manager.get_rule_diff(&existing_rules, &rules_from_config);
    log::info!("Will add {} and delete {} IPtables Rules .. {} are the same.", overview.added.len().to_string().green(), overview.deleted.len().to_string().red(), overview.same.len().to_string().white());
    manager.sync(&overview);
   // manager.add_iptables_rule(&config.priority_ports.first().unwrap());
    let rules = manager.list_rules();


    //d.add_route("10.0.0.2", "eth0", "10.0.0.1")

}



