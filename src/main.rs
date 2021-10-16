mod iptables;
mod route;
mod cfg;
mod util;

extern crate serde;
extern crate serde_yaml;
extern crate regex;
extern crate lazy_static;
extern crate log;
extern crate env_logger;
extern crate colored;
extern crate anyhow;
extern crate thiserror;
extern crate itertools;

use std::collections::{HashSet};
use serde_yaml::from_reader;
use std::process::{Command};
use regex::Regex;
use lazy_static::lazy_static;
use colored::Colorize;
use crate::iptables::*;
use crate::route::*;
use crate::cfg::{Config};
use crate::anyhow::{Context,Result};
use crate::util::ProcOutput;
use crate::itertools::Itertools;

lazy_static! {
    static ref IPTABLES_REGEX: Regex = Regex::new(r"-A PREROUTING -s (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}) -i (.*?) -p (udp|tcp) (--?ma?t?c?h? multiport( ! | )--dports (.*) -j MARK --set-x?mark 0?x?(\d{1})|-j MARK --set-xmark 0?x?(\d{1}))").unwrap();
    static ref ROUTE_DEV_REGEX: Regex = Regex::new(r"dev ([^ \n]+)").unwrap();
    static ref ROUTE_GATEWAY_REGEX: Regex = Regex::new(r"via ([^ \n]+)").unwrap();
}

fn run() -> Result<()> {
    env_logger::init();
    let whoami = Command::new("whoami").output()?.pexit_ok()?.get_output_as_string().0;
    log::info!("I am: {}", whoami);

    let config_file =  std::fs::File::open("rule_file.yaml")?;
    let config: Config = from_reader(config_file)?;

    let iproute2 = IpRoute2 { config: &config };
    let iptables = IPTablesManager::new(&config);

    let _ = iproute2.setup_nics().context("Could not setup nics")?;

    log::info!("Active Sinks: {}", iproute2.get_active_sinks().into_iter().map(|s| s.name.as_str()).join(","));

    let internal_rules = iproute2.calc_internal_rules_from_config().context("Could not compute internal rules")?;
    let active_rules = iproute2.list_routes()?;
    let diff = iproute2.get_route_diff(&internal_rules, &active_rules);

    log::info!("Will add {} and delete {} IP Rules .. {} are the same.", diff.added.len().to_string().green(), diff.deleted.len().to_string().red(), diff.same.len().to_string().white());

    iproute2.setup_udp_routing_table()?;

    let _: Vec<()> = diff.deleted.into_iter().map(|c| { iproute2.delete_route(c) }).collect::<Result<Vec<_>,_>>().context("ip delete command failed")?;
    let _: Vec<()> = diff.added.into_iter().map(|c| { iproute2.add_route(c) }).collect::<Result<Vec<_>,_>>().context("ip add command failed")?;

    let existing_rules: HashSet<InternalIptablesPortRule> = iptables.list_rules();
    let rules_from_config: HashSet<InternalIptablesPortRule> = iptables.config.priority_ports.iter().map(|p| (p, &iptables.config.homenet).into()).collect();
    let overview = iptables.get_rule_diff(&existing_rules, &rules_from_config);

    log::info!("Will add {} and delete {} IPtables Rules .. {} are the same.", overview.added.len().to_string().green(), overview.deleted.len().to_string().red(), overview.same.len().to_string().white());

    iptables.sync(&overview)?;

    let rules = iptables.list_rules();
    let duped_rules: Vec<_> = iptables.get_dupes(&rules);

    if duped_rules.len() > 0 {
        log::warn!("Found {} duplicated iptables rules, gonna delete them", duped_rules.len().to_string().yellow());
    }

    let _: Vec<()> = duped_rules.into_iter().map(|rule| iptables.delete_iptables_rule(rule)).collect::<Result<Vec<_>,_>>().context("could not delete iptables rule")?;

    iptables.print_summary();
    iproute2.print_summary()?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {:#?}", err);
        std::process::exit(1);
    }
}



