use std::collections::{HashSet, HashMap};
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use crate::cfg::{ParseError, Config, Homenet};
use crate::cfg::PortRule;
use crate::IPTABLES_REGEX;
use thiserror::Error;
use itertools::Itertools;
use std::iter::FromIterator;

#[derive(Error,Debug)]
pub enum IpTablesError {

    #[error("Iptables command failed")]
    ProcessFailed(String)
}

pub struct IPTablesManager<'a> {
    pub(crate)ipt: iptables::IPTables,
    pub(crate) config: &'a Config,
}

pub struct IpTablesRuleDiff<'a> {
    pub(crate) added: Vec<&'a InternalIptablesPortRule>,
    pub(crate) deleted: Vec<&'a InternalIptablesPortRule>,
    pub(crate) same: Vec<&'a InternalIptablesPortRule>
}

#[derive(Debug, Eq, Ord, PartialOrd)]
pub struct InternalIptablesPortRule {
    pub(crate) nic: String,
    pub(crate) source: String,
    pub(crate) protocol: String,
    pub(crate) ports: Option<String>,
    pub(crate) not: Option<bool>,
    pub(crate) mark: u8,
    pub(crate) chain: String
}

impl PartialEq for InternalIptablesPortRule {
    fn eq(&self, other: &Self) -> bool {
            self.nic.eq(&other.nic)
                &&
                self.source.eq(&other.source)
                &&
                self.protocol.eq(&other.protocol)
                &&
                self.ports.eq(&other.ports)
                &&
                self.mark.eq(&other.mark)
                &&
                self.chain.eq(&other.chain)
                &&
                ((self.not == other.not) || (self.not == None && other.not == Some(false)) || (self.not == Some(false) && other.not == None))
    }
}

impl Hash for InternalIptablesPortRule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.not.unwrap_or(false).hash(state);
        self.mark.hash(state);
        self.ports.clone().unwrap_or("".to_string()).hash(state);
        self.protocol.hash(state);
        self.source.hash(state);
        self.nic.hash(state);
        self.chain.hash(state);
    }
}

impl TryFrom<String> for InternalIptablesPortRule {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, ParseError> {
        let capture = IPTABLES_REGEX.captures(&value).ok_or(ParseError::Error("capture not found".to_string()))?;
        let rule = InternalIptablesPortRule {
            nic: capture.get(4).map(|e| e.as_str()).unwrap_or("").to_string(),
            protocol: capture.get(5).map(|e| e.as_str()).ok_or(ParseError::Error("protocol not found".to_string()))?.to_string(),
            source: capture.get(2).map(|e| e.as_str()).ok_or(ParseError::Error("source not found".to_string()))?.to_string(),
            ports: capture.get(8).map(|e| e.as_str().to_string()),
            not: capture.get(7).map(|e| e.as_str()).map( |f| f.to_string().contains("!")),
            mark:  capture.get(10).or_else(|| capture.get(9)).map(|e| e.as_str().parse::<u8>()).ok_or(ParseError::Error("mark not found".to_string()))??,
            chain: capture.get(1).map(|e| e.as_str().to_string()).ok_or(ParseError::Error("chain not found".to_string()))?
        };
        Ok(rule)
    }
}

impl From<&InternalIptablesPortRule> for String {
    fn from(iptables_rule: &InternalIptablesPortRule) -> Self {
        let source = iptables_rule.source.to_string();
        let nic = iptables_rule.nic.to_string();
        let protocol = iptables_rule.protocol.to_string();
        let not = if iptables_rule.not.unwrap_or(false) {" ! "} else { "" };
        let mark = iptables_rule.mark;
        let chain = iptables_rule.chain.to_string();
        let prerouting = "PREROUTING".to_string();

        let mut start = format!("-s {} -p {}", source, protocol);

        if chain.eq(&prerouting) {
            start.push_str(format!(" -i {}", nic).as_str())
        }

        let command = if let Some(dports) = iptables_rule.ports.clone() {
            format!(" -m multiport {} --dports {} -j MARK --set-mark {}", not, dports, mark)
        } else {
            format!(" -j MARK --set-mark {}", mark)
        };

        start.push_str(command.as_str());
        start
    }
}

impl From<(&PortRule,&Homenet)> for InternalIptablesPortRule {
    fn from((rule,homenet): (&PortRule, &Homenet)) -> Self {
        InternalIptablesPortRule {
            nic: if rule.chain.eq("OUTPUT") { "".to_string() } else {  homenet.input_nic.to_string() },
            mark: rule.mark.unwrap_or(1),
            not: rule.not,
            source: homenet.ip.to_string(),
            protocol: rule.protocol.to_string(),
            ports: rule.ports.clone(),
            chain: rule.chain.clone()
        }
    }
}

impl IPTablesManager<'_> {

    pub(crate) fn new(config: &Config) -> IPTablesManager {
        IPTablesManager {
            ipt: iptables::new(false).unwrap(),
            config,
        }
    }

    fn add_iptables_rule(&self, port_rule: &InternalIptablesPortRule) -> Result<(), IpTablesError> {
        let command = String::from(port_rule);
        log::debug!("-A {} {}",&port_rule.chain, command);
        self.ipt.append_unique("mangle", &port_rule.chain, &command).map_err(|_| IpTablesError::ProcessFailed("append command failed".to_string()))
    }

    pub fn delete_iptables_rule(&self, port_rule: &InternalIptablesPortRule) -> Result<(), IpTablesError> {
        let command = String::from(port_rule);
        log::debug!("-D {} {}",&port_rule.chain, command);
        self.ipt.delete("mangle", &port_rule.chain, &command.as_str()).map_err(|_| IpTablesError::ProcessFailed("delete command failed".to_string()))
    }

    /**
    Returns a sorted list of all present rules
    Contains duplicates if return type is a set
    **/
    pub(crate) fn list_rules<T>(&self) -> T where T: FromIterator<InternalIptablesPortRule> {
        self.ipt.list_table("mangle").unwrap()
            .into_iter()
            .map(|rule| InternalIptablesPortRule::try_from(rule))
            .filter(|e| e.is_ok())
            .map(|e| e.unwrap())
            .sorted()
            .collect()
    }

    pub(crate) fn get_dupes<'a>(&self, existing_rules: &'a Vec<InternalIptablesPortRule>) -> Vec<&'a InternalIptablesPortRule> {
        //find rules that might be duplicated for some reason
        let mut map: HashMap<&InternalIptablesPortRule, u32> = HashMap::new();
        existing_rules.iter().for_each(|rule| {
            let entry = map.entry(rule).or_insert(0);
            *entry += 1;
        });

        map.into_iter()
            .filter(|(_, v)| v > &1)
            .flat_map(|(k, v)| (0..(v - 1)).map(|_|k ).collect::<Vec<_>>())
            .collect::<Vec<&InternalIptablesPortRule>>()
    }

    pub(crate) fn get_rule_diff<'a>(&self, existing_rules: &'a HashSet<InternalIptablesPortRule>, rules_from_config: &'a HashSet<InternalIptablesPortRule>) -> IpTablesRuleDiff<'a> {
        let to_delete = existing_rules.difference(rules_from_config).collect();
        let to_add = rules_from_config.difference(&existing_rules).collect();
        let same = rules_from_config.intersection(&existing_rules).collect();

        IpTablesRuleDiff {
            added: to_add,
            deleted: to_delete,
            same
        }
    }

    pub(crate) fn sync(&self, diff: &IpTablesRuleDiff) -> Result<(), IpTablesError> {
        diff.deleted.iter()
            .map(|r| self.delete_iptables_rule(r))
            .collect::<Result<Vec<()>,_>>()
            .and_then(|_| diff.added.iter().map(|r| self.add_iptables_rule(r)).collect::<Result<(), IpTablesError>>())
    }

    pub(crate) fn print_summary(&self) {
        let rules: Vec<InternalIptablesPortRule> = self.list_rules();
        let ports: (Vec<InternalIptablesPortRule>,Vec<InternalIptablesPortRule>) = rules
            .into_iter()
            .filter(|e|e.ports.is_some())
            .partition(|e| e.not.unwrap_or(false) == true);

        log::info!("TCP Ports marked: {}", ports.1.iter().filter(|e| e.protocol.eq("tcp")).filter_map(|e| e.ports.as_ref().map(|p| format!("{} [{}]",p,e.mark))).collect::<Vec<_>>().join(", "));
        log::info!("UDP Ports marked: {}", ports.1.iter().filter(|e| e.protocol.eq("udp")).filter_map(|e| e.ports.as_ref().map(|p| format!("{} [{}]",p,e.mark))).collect::<Vec<_>>().join(", "));
        log::info!(" ");
        log::info!("TCP ports that are NOT getting marked {}", ports.0.iter().filter(|e| e.protocol.eq("tcp")).filter_map(|e| e.ports.as_ref().map(|p| format!("{} [{}]",p,e.mark))).collect::<Vec<_>>().join(", "));
        log::info!("UDP ports that are NOT getting marked {}", ports.0.iter().filter(|e| e.protocol.eq("udp")).filter_map(|e| e.ports.as_ref().map(|p| format!("{} [{}]",p,e.mark))).collect::<Vec<_>>().join(", "));

    }
}

#[cfg(test)]
mod tests {
    use crate::iptables::{InternalIptablesPortRule, IPTablesManager};
    use crate::cfg::Config;
    use serde_yaml::from_reader;

    #[test]
    fn test_dupe_detection_1_dupe() {

        let rule1 = InternalIptablesPortRule {
            nic: "eth0".to_string(),
            source: "1.1.1.1".to_string(),
            protocol: "udp".to_string(),
            ports: Some("1,3".to_string()),
            not: None,
            mark: 1,
            chain: "PREROUTING".to_string()
        };

        let rule2 = InternalIptablesPortRule {
            nic: "eth0".to_string(),
            source: "1.1.1.1".to_string(),
            protocol: "udp".to_string(),
            ports: Some("1,3".to_string()),
            not: None,
            mark: 1,
            chain: "PREROUTING".to_string()
        };

        let vec = vec![rule1,rule2];

        let f =  std::fs::File::open("test_udp_rule_lte.yml").unwrap();
        let config: Config = from_reader(f).unwrap();

        let manager = IPTablesManager::new(&config);
        let rules = manager.get_dupes(&vec);
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_dupe_detection_0_dupe() {

        let rule1 = InternalIptablesPortRule {
            nic: "eth0".to_string(),
            source: "1.1.1.1".to_string(),
            protocol: "udp".to_string(),
            ports: Some("1,3".to_string()),
            not: None,
            mark: 1,
            chain: "PREROUTING".to_string()
        };

        let vec = vec![rule1];

        let f =  std::fs::File::open("test_udp_rule_lte.yml").unwrap();
        let config: Config = from_reader(f).unwrap();

        let manager = IPTablesManager::new(&config);
        let rules = manager.get_dupes(&vec);
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_dupe_detection_2_different_dupes() {

        let rule11 = InternalIptablesPortRule {
            nic: "eth0".to_string(),
            source: "1.1.1.1".to_string(),
            protocol: "udp".to_string(),
            ports: Some("1,3".to_string()),
            not: None,
            mark: 1,
            chain: "PREROUTING".to_string()
        };

        let rule12 = InternalIptablesPortRule {
            nic: "eth0".to_string(),
            source: "1.1.1.1".to_string(),
            protocol: "udp".to_string(),
            ports: Some("1,3".to_string()),
            not: None,
            mark: 1,
            chain: "PREROUTING".to_string()
        };

        let rule21 = InternalIptablesPortRule {
            nic: "eth0".to_string(),
            source: "1.1.1.2".to_string(),
            protocol: "udp".to_string(),
            ports: Some("1,3".to_string()),
            not: None,
            mark: 1,
            chain: "PREROUTING".to_string()
        };

        let rule22 = InternalIptablesPortRule {
            nic: "eth0".to_string(),
            source: "1.1.1.2".to_string(),
            protocol: "udp".to_string(),
            ports: Some("1,3".to_string()),
            not: None,
            mark: 1,
            chain: "PREROUTING".to_string()
        };


        let vec = vec![rule11,rule12,rule21,rule22];

        let f =  std::fs::File::open("test_udp_rule_lte.yml").unwrap();
        let config: Config = from_reader(f).unwrap();

        let manager = IPTablesManager::new(&config);
        let rules = manager.get_dupes(&vec);
        assert_eq!(rules.len(), 2);
    }
}