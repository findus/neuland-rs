use std::collections::HashSet;
use std::convert::TryFrom;
use std::error::Error;
use crate::cfg::{ParseError, Config, Homenet};
use crate::cfg::PortRule;
use crate::IPTABLES_REGEX;
use thiserror::Error;

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

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct InternalIptablesPortRule {
    pub(crate) nic: String,
    pub(crate) source: String,
    pub(crate) protocol: String,
    pub(crate) ports: Option<String>,
    pub(crate) not: Option<bool>,
    pub(crate) mark: u8
}

impl TryFrom<String> for InternalIptablesPortRule {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, ParseError> {
        let capture = IPTABLES_REGEX.captures(&value).ok_or(ParseError::Error("capture not found".to_string()))?;
        let d = InternalIptablesPortRule {
            nic: capture.get(2).map(|e| e.as_str()).ok_or(ParseError::Error("nic not found".to_string()))?.to_string(),
            protocol: capture.get(3).map(|e| e.as_str()).ok_or(ParseError::Error("protocol not found".to_string()))?.to_string(),
            source: capture.get(1).map(|e| e.as_str()).ok_or(ParseError::Error("source not found".to_string()))?.to_string(),
            ports: capture.get(6).map(|e| e.as_str().to_string()),
            not: capture.get(5).map(|e| e.as_str()).map( |f| f.to_string().contains("!")),
            mark:  capture.get(8).or_else(|| capture.get(7)).map(|e| e.as_str().parse::<u8>()).ok_or(ParseError::Error("mark not found".to_string()))??
        };
        Ok(d)
    }
}

impl From<&InternalIptablesPortRule> for String {
    fn from(iptables_rule: &InternalIptablesPortRule) -> Self {
        let source = iptables_rule.source.to_string();
        let nic = iptables_rule.nic.to_string();
        let protocol = iptables_rule.protocol.to_string();
        let not = if iptables_rule.not.unwrap_or(false) {" ! "} else { "" };
        let mark = iptables_rule.mark;
        if let Some(dports) = iptables_rule.ports.clone() {
            format!("-s {} -i {} -p {} -m multiport {} --dports {} -j MARK --set-mark {}",source, nic, protocol,not, dports, mark)
        } else {
            format!("-s {} -i {} -p {} -j MARK --set-mark {}",source, nic, protocol, mark)
        }
    }
}

impl From<(&PortRule,&Homenet)> for InternalIptablesPortRule {
    fn from((rule,homenet): (&PortRule, &Homenet)) -> Self {
        InternalIptablesPortRule {
            nic: homenet.input_nic.to_string(),
            mark: rule.mark.unwrap_or(1),
            not: rule.not,
            source: homenet.ip.to_string(),
            protocol: rule.protocol.to_string(),
            ports: rule.ports.clone()
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
        self.ipt.append_unique("mangle", "PREROUTING", &command).map_err(|e| IpTablesError::ProcessFailed("append command failed".to_string()))
    }

    fn delete_iptables_rule(&self, port_rule: &InternalIptablesPortRule) -> Result<(), IpTablesError> {
        let command = String::from(port_rule);
        self.ipt.delete("mangle", "PREROUTING", &command.as_str()).map_err(|e| IpTablesError::ProcessFailed("append command failed".to_string()))
    }

    pub(crate) fn list_rules(&self) -> HashSet<InternalIptablesPortRule> {
        self.ipt.list_table("mangle").unwrap()
            .into_iter()
            .map(|rule| InternalIptablesPortRule::try_from(rule))
            .filter(|e| e.is_ok())
            .map(|e| e.unwrap())
            .collect()
    }

    pub(crate) fn get_rule_diff<'a>(&self, existing_rules: &'a HashSet<InternalIptablesPortRule>, rules_from_config: &'a HashSet<InternalIptablesPortRule>) -> IpTablesRuleDiff<'a> {
        let to_delete = existing_rules.difference(&rules_from_config).collect();
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
        let rules = self.list_rules();
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