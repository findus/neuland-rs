use std::error::Error;
use std::num::ParseIntError;
use std::process::{Command, ExitStatus, Output};
use crate::cfg::ParseError;
use crate::thiserror::Error;

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
            let output =  self.get_output_as_string().1;
            log::error!("Command failed: {}", output);
            Err(ProcessError::CommandFailed(self.status.code().unwrap(), output))
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

pub trait ToCmd {
    fn args_with_log(self, args: &str) -> Command;
}

impl ToCmd for Command {
    fn args_with_log(mut self, args: &str) -> Command {
        let vec = args.split(" ");
        self.args(vec);
        log::debug!("{}", format!("cmd: {:?}", &self).replace("\"",""));
        self
    }
}

#[cfg(test)]
mod test {
    use std::process::Command;
    use super::ToCmd;

    #[test]
    fn cmd() {
        env_logger::init();
        Command::new("ip").args_with_log("a");
    }
}