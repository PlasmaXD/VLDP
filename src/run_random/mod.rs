//! Functionality to run a server and client for any of our VLDP schemes (Base, Extend, Shuffle)
//! locally on randomly generated inputs (trusted environment and communication are emulated).

mod run_protocol_base;
pub use run_protocol_base::*;

mod run_protocol_expand;
pub use run_protocol_expand::*;

mod run_protocol_shuffle;
pub use run_protocol_shuffle::*;
