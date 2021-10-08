use std::num::ParseIntError;
use std::process::{ExitStatus, Output};
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