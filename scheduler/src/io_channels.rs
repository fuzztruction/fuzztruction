//! The different channels used by applications to read or write data.

use serde::Serialize;

/// The kind of input the program consumes.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub enum InputChannel {
    /// The program does not consume any input at all.
    None,
    /// Input is consumed via stdin.
    Stdin,
    /// Input is consumed via a file. The argument that is replaced by the
    /// path to the input file must be marked with @@.
    File,
}

/// The kind of output a program produces.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize)]
pub enum OutputChannel {
    /// Program does not produce any output.
    None,
    /// Output is send to stdout.
    Stdout,
    /// Output is written into a file. The argument representing the file path
    /// is marked as §§.
    File,
}
