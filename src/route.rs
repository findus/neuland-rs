use std::convert::TryFrom;
use std::collections::{HashSet};
use std::process::Command;
use std::fs::{OpenOptions, File};
use crate::cfg::{Config, ParseError, Sink, IPRule, Nic};
use std::io::Read;
use std::io::Write;
use crate::ROUTE_DEV_REGEX;
use crate::ROUTE_GATEWAY_REGEX;
use crate::thiserror::Error;
use crate::util::{ProcOutput, ToCmd};
use crate::util::ProcessError;
use itertools::Itertools;
use std::path::Path;

#[derive(Error,Debug)]
pub enum IpRouteError {
    #[error("No routes available from config")]
    NoRoutesAvailable,
    #[error(transparent)]
    CommandError(#[from] std::io::Error),
    #[error(transparent)]
    ProcessFailed(#[from] ProcessError)
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

    pub(crate) fn setup_nics(&self) -> Result<Vec<()>, IpRouteError> {
        self.config.nics.iter()
            .filter(|nic| self.is_present(nic))
            .map(|nic| {
            if self.is_nic_up(nic)? == false || self.nic_has_ip(nic)? == false || self.nic_has_same_ip_as_config(nic)? == false {
                log::info!("Will configure NIC {}", nic.nic);
                self.get_cmd().args_with_log(&format!("link set {} up", &nic.nic)).output()?.pexit_ok()?;
                self.get_cmd().args_with_log(&format!("addr flush {}", &nic.nic)).output()?.pexit_ok()?;
                self.get_cmd().args_with_log(&format!("addr add {} dev {}", &nic.ip, &nic.nic)).output()?.pexit_ok()?;
                Ok(())
            } else {
                log::info!("NIC already configured: {}", nic.nic);
                Ok(())
            }
        }).collect()
    }

    fn is_present(&self, nic: &Nic) -> bool {
        let path = format!("/sys/class/net/{}", nic.nic);
        Path::new(&path).exists()
    }

    fn is_nic_up(&self, nic: &Nic) -> Result<bool, IpRouteError> {
        let out = self.get_cmd().args_with_log(&format!("link show {}", &nic.nic)).output()?.pexit_ok()?.get_output_as_string();
        Ok(out.0.contains("state UP") == true)
    }

    fn nic_has_ip(&self, nic: &Nic) -> Result<bool, IpRouteError>  {
        let out = self.get_cmd().args_with_log(&format!("-f inet addr show {}", &nic.nic)).output()?.pexit_ok()?.get_output_as_string();
        Ok(out.0.contains("state UP") == true)
    }

    fn nic_has_same_ip_as_config(&self, nic: &Nic) -> Result<bool, IpRouteError>  {
        let out = self.get_cmd().args_with_log(&format!("-f inet addr show {}", &nic.nic)).output()?.pexit_ok()?.get_output_as_string();
        Ok(out.0.contains(&nic.ip) == true)
    }

    fn rule_active(&self) -> bool {
        let out = String::from_utf8(self.get_cmd().args_with_log(&"rule").output().unwrap().stdout).unwrap();
        out.contains("udp_routing_table")
    }

    pub fn get_active_sinks(&self) -> Vec<&Sink> {
        self.config.sinks
            .iter()
            .filter( |sink| sink.active.unwrap_or(true))
            .filter( |sink| {
                let out = self.get_cmd().args_with_log(&format!("link show {}", &sink.nic)).output();
                out.is_ok() && out.unwrap().get_output_as_string().0.contains("state")
            })
            .collect()
    }

    pub(crate) fn setup_udp_routing_table(&self) -> Result<(), IpRouteError> {
        log::info!("Check UDP Routing table state...");
        let mut file = String::new();
        File::open("/etc/iproute2/rt_tables")?.read_to_string(&mut file)?;
        if file.contains("udp_routing_table") == false {
            log::info!("UDP Routing table does not exist, gonna create it.");
            let mut file = OpenOptions::new().write(true).append(true).open("/etc/iproute2/rt_tables")?;
            writeln!(file, "201 udp_routing_table")?
        }

        if self.rule_active() == false {
            log::info!("Adding fwmark rule to routing table");
            self.get_cmd().args_with_log(&"rule add fwmark 1 table udp_routing_table").output()?.pexit_ok()?;
        }

        if self.get_cmd().args_with_log(&"route show table udp_routing_table").output()?.pexit_ok().is_err() {
            self.get_cmd().args_with_log(&"route add default dev lo table udp_routing_table").output()?.pexit_ok()?;
            self.get_cmd().args_with_log(&"route delete default dev lo table udp_routing_table").output()?.pexit_ok()?;
        }

        Ok(())
    }


    fn get_cmd(&self) -> Command {
        Command::new("ip")
    }

    pub(crate) fn calc_internal_rules_from_config(&self) -> Result<HashSet<InternalIpRule>,IpRouteError> {

        let sinks = self.get_active_sinks();
        let set = self.config.priority_ip.iter().map(|rule| {
            let sink = self.get_first_avaliable_sink(&sinks, rule);

            if sink.is_none() {
                log::warn!("Could not find a sink for rule '{}'", &rule.name );
            }

            sink.map(|sinkname| sinks.iter().filter(|s| s.name.eq(&sinkname)).nth(0))
                .flatten()
                .map(|sink| {
                    log::info!("Sink for {}: {}", rule.name, sink.name);
                    rule.ips.iter().map(|r| {
                        InternalIpRule {
                            nic: (&sink.nic).to_string(),
                            ip: (r).to_string(),
                            gateway: Some((&sink.ip).to_string()),
                            table: rule.table.clone(),
                        }
                    }).collect::<HashSet<_>>()
                })
        })
            .flatten()
            .flatten()
            .collect::<HashSet<_>>();

        if set.is_empty() {
            Err(IpRouteError::NoRoutesAvailable)
        } else {
            Ok(set)
        }
    }

    fn get_first_avaliable_sink(&self, sinks: &Vec<&Sink>, rule: &IPRule) -> Option<String> {
        if rule.name.eq("udp") == false {
            rule.priority.iter().filter_map(|name| sinks.iter().find(|e| e.name.eq(name))).nth(0).map(|entry| entry.name.clone())
        } else {
            rule.priority.iter().filter_map(|name| sinks.iter().find(|e| e.name.eq(name) && e.udp)).nth(0).map(|entry| entry.name.clone())
        }
    }

    pub(crate) fn list_routes(&self) -> Result<HashSet<InternalIpRule>, IpRouteError> {
        let  stdout = self.get_cmd().args_with_log("route").output()?.pexit_ok()?.get_output_as_string().0;
        let  stdout_udp = self.get_cmd().args_with_log(&"route show table udp_routing_table").output()?.pexit_ok()?.get_output_as_string().0;

        if stdout.len() == 0 {
            return Ok(HashSet::new());
        }

        let mut rules: HashSet<_> = stdout
            .trim()
            .split('\n')
            .map(String::from)
            .map(|str| InternalIpRule::try_from(str).unwrap())
            //dont delete nexthop
            .filter(|rule| rule.ip.eq(&self.config.homenet.ip) == false)
            //ignore rules that we dont care about like wireguard rules
            .filter(|rule| *&self.config.nics.iter().map(|e| e.nic.clone()).contains::<String>(&rule.nic.to_string()))
            .collect();

        let udp_rules: HashSet<_> = stdout_udp
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
        Ok(rules)
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

    pub(crate) fn add_route(&self, rule: &InternalIpRule) -> Result<(), IpRouteError> {
        let mut command = self.get_cmd().args_with_log(&format!("route add {}", String::from(rule)));
        command.output()?.pexit_ok()?;
        Ok(())
    }

    pub(crate) fn delete_route(&self, rule: &InternalIpRule) -> Result<(), IpRouteError> {
        let mut command = self.get_cmd().args_with_log(&format!("route delete {}", String::from(rule)));
        command.output()?.pexit_ok()?;
        Ok(())
    }

    pub(crate) fn print_summary(&self) -> Result<(),IpRouteError> {
        let  stdout = self.get_cmd().args_with_log("route").output()?.pexit_ok()?.get_output_as_string().0;
        let  stdout_udp = self.get_cmd().args_with_log(&"route show table udp_routing_table").output()?.pexit_ok()?.get_output_as_string().0;

        log::info!("Routing table:");
        stdout.split("\n").for_each(|e| log::info!("{}", e));
        log::info!(" ");
        log::info!("UDP Routing table:");
        stdout_udp.split("\n").for_each(|e| log::info!("{}", e));
        Ok(())
    }

    #[allow(unused)]
    pub(crate) fn check_gateway(&self, nic: &str, gateway: &str) -> Result<(), IpRouteError> {
        let mut cmd = self.get_cmd();
        let mut command =  cmd.args_with_log(&format!("route add default via {} dev {}", gateway, nic));
        command.output()?.pexit_ok()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::cfg::{Config, IPRule};
    use serde_yaml::from_reader;
    use crate::route::{InternalIpRule, IpRoute2};

    #[test]
    fn route_test() {
        let f =  std::fs::File::open("test_udp_rule_lte.yml").unwrap();
        let config: Config = from_reader(f).unwrap();
        let iproute2 = IpRoute2{ config: &config };

        let internal_route = InternalIpRule {
            nic: "u".to_string(),
            ip: "u".to_string(),
            gateway: None,
            table: None
        };

        let result = iproute2.delete_route(&internal_route);
        assert!(matches!(result, Err(_)))
    }

    #[test]
    fn ip_add_error_test() {
        let f =  std::fs::File::open("test_udp_rule_lte.yml").unwrap();
        let config: Config = from_reader(f).unwrap();
        let iproute2 = IpRoute2{ config: &config };

        let internal_route = InternalIpRule {
            nic: "u".to_string(),
            ip: "u".to_string(),
            gateway: None,
            table: None
        };

        let result = iproute2.add_route(&internal_route);
        assert!(matches!(result, Err(_)))
    }

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
        assert!(active_sink.is_some());
        assert_eq!(active_sink.unwrap().as_str(),"lte")

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
        assert!(active_sink.is_some());
        assert_eq!(active_sink.unwrap().as_str(),"adsl")

    }


}
