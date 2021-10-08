mod iptables;
mod route;
mod cfg;

extern crate serde;
extern crate serde_yaml;
extern crate regex;
extern crate lazy_static;
extern crate log;
extern crate env_logger;
extern crate colored;
extern crate thiserror;
extern crate anyhow;

use std::collections::{HashSet};
use std::io::Error;
use std::num::ParseIntError;
use serde_yaml::from_reader;
use std::process::{Command, ExitStatus, Output};
use regex::Regex;
use lazy_static::lazy_static;
use colored::Colorize;
use crate::iptables::*;
use crate::route::*;
use crate::cfg::{ParseError, Config};
use crate::thiserror::Error;

lazy_static! {
    static ref IPTABLES_REGEX: Regex = Regex::new(r"-A PREROUTING -s (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) -i (.*?) -p (udp|tcp) (--?ma?t?c?h? multiport( ! | )--dports (.*) -j MARK --set-x?mark 0?x?(\d{1})|-j MARK --set-xmark 0?x?(\d{1}))").unwrap();
    static ref ROUTE_DEV_REGEX: Regex = Regex::new(r"dev ([^ \n]+)").unwrap();
    static ref ROUTE_GATEWAY_REGEX: Regex = Regex::new(r"via ([^ \n]+)").unwrap();
}

#[derive(Error,Debug)]
pub enum ProcessError {
    #[error("Process exited with error")]
    CommandFailed(i32, String),
}


impl From<ParseIntError> for ParseError {
    fn from(e: ParseIntError) -> Self {
        ParseError::Error(e.to_string())
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

pub trait ProcOutput {
    fn get_output_as_string(&self) -> (String, String, ExitStatus);
    fn pexit_ok(self) -> Result<Self, ProcessError> where Self: Sized;
}

impl ProcOutput for Output {
    fn get_output_as_string(&self) -> (String, String, ExitStatus) {
        (self.stdout.to_formatted_string(), self.stderr.to_formatted_string(), self.status)
    }

    fn pexit_ok(self) -> Result<Self, ProcessError> {
        if self.status.success() {
            Ok(self)
        } else {
            Err(ProcessError::CommandFailed(self.status.code().unwrap(), self.get_output_as_string().1))
        }
    }
}

pub trait VecToString {
    fn to_formatted_string(&self) -> String;
}

impl VecToString for Vec<u8> {
    fn to_formatted_string(&self) -> String {
        String::from_utf8_lossy(self)
            .trim()
            .to_string()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let whoami = Command::new("whoami").output()?.get_output_as_string().0;
    println!("{}", whoami);

    let f =  std::fs::File::open("rule_file.yaml")?;
    let config: Config = from_reader(f)?;

    let iproute2 = IpRoute2{ config: &config };

    let b = iproute2.calc_internal_rules_from_config();
    let active = &iproute2.list_routes();
    let a = iproute2.get_route_diff(&b, &active);

    log::info!("Will add {} and delete {} IP Rules .. {} are the same.", a.added.len().to_string().green(), a.deleted.len().to_string().red(), a.same.len().to_string().white());

    let array  = iproute2.setup_nics();
    if array.len() > 0 {
        array.iter().for_each(|e| {
            eprint!("Setting up NICs failed: {:?}", e);
        });
    }


    iproute2.setup_udp_routing_table();

    a.deleted.iter().for_each(|c| {
        iproute2.delete_route(c).unwrap()
    });


    a.added.iter().for_each(|c| {
        iproute2.add_route(c).unwrap();
    });


    let manager = IPTablesManager::new(&config);

    let existing_rules: HashSet<InternalIptablesPortRule> = manager.list_rules();
    let rules_from_config: HashSet<InternalIptablesPortRule> = manager.config.priority_ports.iter().map(|p| (p, &manager.config.homenet).into()).collect();
    let overview = manager.get_rule_diff(&existing_rules, &rules_from_config);
    log::info!("Will add {} and delete {} IPtables Rules .. {} are the same.", overview.added.len().to_string().green(), overview.deleted.len().to_string().red(), overview.same.len().to_string().white());
    manager.sync(&overview);
    manager.print_summary();
    Ok(())
}



