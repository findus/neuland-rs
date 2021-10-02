use std::convert::TryFrom;
use std::collections::{HashSet};
use crate::print_output;
use std::process::Command;
use std::fs::{OpenOptions, File};
use crate::cfg::{Config, ParseError, Sink, IPRule, Nic};
use std::io::Read;
use std::io::Write;
use crate::ROUTE_DEV_REGEX;
use crate::ROUTE_GATEWAY_REGEX;

#[derive(Debug,PartialEq)]
pub enum IpRouteError {
    Error(String)
}

pub struct IpRoute2<'a> {
    pub(crate) config: &'a Config,
}

pub struct IpRuleDiff<'a> {
    pub(crate) added: Vec<&'a InternalIpRule>,
    pub(crate) deleted: Vec<&'a InternalIpRule>,
    pub(crate) same: Vec<&'a InternalIpRule>
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct InternalIpRule {
    nic: String,
    ip: String,
    gateway: Option<String>,
    table: Option<String>
}

impl TryFrom<String> for InternalIpRule {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let dev_capture = ROUTE_DEV_REGEX.captures(&value).ok_or(ParseError::Error("device_capture not found".to_string()))?;
        let gw_capture = ROUTE_GATEWAY_REGEX.captures(&value);

        let ip = value.split(" ").into_iter().nth(0).unwrap().to_string();
        let device = dev_capture.get(1).map(|e| e.as_str()).ok_or(ParseError::Error("device not found".to_string()))?.to_string();
        let gateway =  gw_capture.and_then(|c| c.get(1).map(|e| e.as_str()));

        Ok(InternalIpRule {
            nic: device,
            ip,
            gateway: gateway.map(|e| e.to_string()),
            table: None
        })
    }
}


impl From<&InternalIpRule> for String {
    fn from(rule: &InternalIpRule) -> Self {
        let mut str = format!("{}",rule.ip);
        if rule.gateway.is_some() {
            str.push_str(&format!(" via {}", (&rule).gateway.as_ref().unwrap()));
        }
        str.push_str(&format!(" dev {}", (&rule).nic));

        if let Some(table) = rule.table.as_ref().map(|e| e.to_string()) {
            str.push_str(&format!(" table {}", table));
        }

        str
    }
}

impl IpRoute2<'_> {

    pub(crate) fn setup_nics(&self) {
        self.config.nics.iter().for_each(|nic| {
            if self.is_nic_up(nic) == false || self.nic_has_ip(nic) == false {
                log::info!("Will configure NIC {}", nic.nic);
                let out = self.get_cmd().args(&["link", "set", &nic.nic, "up"]).output().unwrap();
                let o = out.stderr;
                print_output(o);
                let out = self.get_cmd().args(&["addr", "flush", &nic.nic]).output().unwrap();
                let o = out.stderr;
                print_output(o);
                let out = self.get_cmd().args(&["addr", "add", &nic.ip, "dev", &nic.nic]).output().unwrap();
                let o = out.stderr;
                print_output(o);
            } else {
                log::info!("NIC already configured: {}", nic.nic);
            }
        });
    }

    fn is_nic_up(&self, nic: &Nic) -> bool {
        let out = String::from_utf8(self.get_cmd().args(&["link", "show", &nic.nic]).output().unwrap().stdout).unwrap();
        out.contains("state UP") == true
    }

    fn nic_has_ip(&self, nic: &Nic) -> bool {
        let out = String::from_utf8(self.get_cmd().args(&["-f", "inet", "addr", "show", &nic.nic]).output().unwrap().stdout).unwrap();
        out.contains(&nic.ip)
    }

    fn rule_active(&self) -> bool {
        let out = String::from_utf8(self.get_cmd().args(&["rule"]).output().unwrap().stdout).unwrap();
        out.contains("udp_routing_table")
    }

    fn get_active_sinks(&self) -> Vec<&Sink> {
        self.config.sinks
            .iter()
            .filter( |sink| String::from_utf8(self.get_cmd().args(&["link", "show", &sink.nic]).output().unwrap().stdout).unwrap().contains("state"))
            .collect()
    }

    pub(crate) fn setup_udp_routing_table(&self) {
        let mut file = String::new();
        File::open("/etc/iproute2/rt_tables").unwrap().read_to_string(&mut file).unwrap();
        if file.contains("udp_routing_table") == false {
            log::info!("UDP Routing table does not exist, gonna create it.");
            let mut file = OpenOptions::new().write(true).append(true).open("/etc/iproute2/rt_tables").unwrap();

            if let Err(e) = writeln!(file, "201 udp_routing_table") {
                log::error!("Could not write to file {}", e);
                panic!();
            }

        }

        if self.rule_active() == false {
            log::info!("Adding fwmark rule to routing table");
            self.get_cmd().args(&["rule", "add", "fwmark", "1", "table", "udp_routing_table"]).output().unwrap();
        }

    }


    fn get_cmd(&self) -> Command {
        Command::new("ip")
    }

    pub(crate) fn calc_internal_rules_from_config(&self) -> HashSet<InternalIpRule> {
        let sinks = self.get_active_sinks();

        self.config.priority_ip.iter().map(|rule| {

            let first_available_sink = self.get_first_avaliable_sink(&sinks, rule);
            let sink = sinks.iter().filter(|s| s.name.eq(&first_available_sink)).nth(0).unwrap();
            log::info!("Sink for {}: {}", rule.name, sink.name);
            rule.ips.iter().map(|r| {
                InternalIpRule {
                    nic: (&sink.nic).to_string(),
                    ip: (r).to_string(),
                    gateway: Some((&sink.ip).to_string()),
                    table: rule.table.clone()
                }
            }).collect::<HashSet<_>>()
        }).flatten().collect()
    }

    fn get_first_avaliable_sink(&self, sinks: &Vec<&Sink>, rule: &IPRule) -> String {
        let first_available_sink = if rule.name.eq("udp") == false {
            rule.priority.iter().filter_map(|name| sinks.iter().find(|e| e.name.eq(name))).nth(0).unwrap().name.to_string()
        } else {
            rule.priority.iter().filter_map(|name| sinks.iter().find(|e| e.name.eq(name) && e.udp)).nth(0).unwrap().name.to_string()
        };
        first_available_sink.to_string()
    }

    pub(crate) fn list_routes(&self) -> HashSet<InternalIpRule> {
        let  stdout = self.get_cmd().arg("route").output().unwrap().stdout;
        let  stdout_udp = self.get_cmd().args(&["route","show", "table", "udp_routing_table"]).output().unwrap().stdout;

        if stdout.len() == 0 {
            return HashSet::new();
        }

        let mut rules: HashSet<_> = String::from_utf8_lossy(stdout.as_slice())
            .trim()
            .split('\n')
            .map(String::from)
            .map(|str| InternalIpRule::try_from(str).unwrap())
            //dont delete nexthop
            .filter(|rule| rule.ip.eq(&self.config.homenet.ip) == false)
            //ignore rules that we dont care about like wireguard rules
            .filter(|rule| rule.nic.eq(&self.config.homenet.input_nic))
            .collect();

        let udp_rules: HashSet<_> = String::from_utf8_lossy(stdout_udp.as_slice())
            .trim()
            .split('\n')
            .map(String::from)
            .filter(|e| e.is_empty() == false)
            .map(|str| {

                let mut temp = InternalIpRule::try_from(str).unwrap();
                temp.table = Some("udp_routing_table".to_string());
                temp
            })
            //dont delete nexthop
            .filter(|rule| rule.ip.eq(&self.config.homenet.ip) == false)
            //ignore rules that we dont care about like wireguard rules
            .filter(|rule| rule.nic.eq(&self.config.homenet.input_nic))
            .collect();

        rules.extend(udp_rules);
        rules
    }

    pub(crate) fn get_route_diff<'a>(&self, rules_from_config: &'a HashSet<InternalIpRule>, existing_rules: &'a HashSet<InternalIpRule>) -> IpRuleDiff<'a> {
        let to_delete = existing_rules.difference(&rules_from_config).collect();
        let to_add = rules_from_config.difference(&existing_rules).collect();
        let same = rules_from_config.intersection(&existing_rules).collect();

        IpRuleDiff {
            added: to_add,
            deleted: to_delete,
            same
        }
    }

    pub(crate) fn add_route(&self, rule: &InternalIpRule) {
        let mut cmd = self.get_cmd();
        let e = (&mut cmd).arg("route").arg("add").args(String::from(rule).split(" "));
        log::debug!("{:#?}",e);
        let o = e.output().unwrap().stderr;
        print_output(o);
    }

    pub(crate) fn delete_route(&self, rule: &InternalIpRule) {
        let mut cmd = self.get_cmd();
        let e = (&mut cmd).arg("route").arg("delete").args(String::from(rule).split(" "));
        log::debug!("{:#?}",e);
        let o = e.output().unwrap().stderr;
        print_output(o);
    }

    #[allow(unused)]
    pub(crate) fn check_gateway(&self, nic: &str, gateway: &str) -> Result<(), IpRouteError> {
        let output =  self.get_cmd().arg("route").arg("add").arg("default").arg("via").arg(gateway).arg("dev").arg(nic).output().unwrap();

        let message =  String::from_utf8(output.stderr).unwrap();

        if output.status.success() {
            Ok(())
        } else {
            Err(IpRouteError::Error(message))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::cfg::{Config, IPRule};
    use serde_yaml::from_reader;
    use crate::route::IpRoute2;

    #[test]
    fn udp_priority_lte() {
        let f =  std::fs::File::open("test_udp_rule_lte.yml").unwrap();
        let config: Config = from_reader(f).unwrap();
        let iproute2 = IpRoute2{ config: &config };

        let rule = IPRule {
            priority: vec!["lte".to_string(), "adsl".to_string()],
            ips: vec!["1.1.1.1".to_string()],
            name: "udp".to_string(),
            table: Some("udp_routing_table".to_string())
        };

        let active_sink_map = iproute2.get_active_sinks();

        let active_sink = iproute2.get_first_avaliable_sink(&active_sink_map, &rule);

        let sink_name = &active_sink_map.iter().filter(|s| s.name.eq(&active_sink)).nth(0).unwrap().name;
        assert_eq!("lte", sink_name);
    }

    #[test]
    fn udp_priority_adsl() {
        let f =  std::fs::File::open("test_udp_rule_adsl.yml").unwrap();
        let config: Config = from_reader(f).unwrap();
        let iproute2 = IpRoute2{ config: &config };

        let rule = IPRule {
            priority: vec!["adsl".to_string(), "lte".to_string()],
            ips: vec!["1.1.1.1".to_string()],
            name: "udp".to_string(),
            table: Some("udp_routing_table".to_string())
        };

        let active_sink_map = iproute2.get_active_sinks();

        let active_sink = iproute2.get_first_avaliable_sink(&active_sink_map, &rule);

        let sink_name = &active_sink_map.iter().filter(|s| s.name.eq(&active_sink)).nth(0).unwrap().name;
        assert_eq!("adsl", sink_name);
    }
}
