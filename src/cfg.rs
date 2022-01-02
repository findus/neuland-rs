use serde::Serialize;
use serde::Deserialize;
use crate::InternalIptablesPortRule;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Homenet {
    pub(crate) ip: String,
    pub(crate) input_nic: String
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct Sink {
    pub(crate) name: String,
    pub(crate) ip: String,
    pub(crate) nic: String,
    pub(crate) udp: bool,
    pub(crate) active: Option<bool>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub(crate) homenet: Homenet,
    pub(crate) nics: Vec<Nic>,
    pub(crate) sinks: Vec<Sink>,
    pub(crate) priority_ports: Vec<PortRule>,
    pub(crate) priority_ip: Vec<IPRule>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Nic {
    pub(crate) nic: String,
    pub(crate) ip: String,
}

#[derive(Debug,PartialEq)]
pub enum ParseError {
    Error(String)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct IPRule {
    pub(crate) priority: Vec<String>,
    pub(crate) ips: Vec<String>,
    pub(crate) name: String,
    pub(crate) table: Option<String>
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PortRule {
    pub(crate) not: Option<bool>,
    length: Option<String>,
    pub(crate) ports: Option<String>,
    pub(crate) protocol: String,
    pub(crate) mark: Option<u8>
}