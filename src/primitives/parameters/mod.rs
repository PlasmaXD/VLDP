//! VLDP specific parameters that are used inside the proofs. Implements convenient parameter struct
//! for regular usage and also includes R1CS constraint generation for these parameters.
//! Parameter structs are unique per scheme (Base, Expand, Shuffle).
pub mod base;
pub use base::*;

pub mod expand;
pub use expand::*;

pub mod shuffle;
pub use shuffle::*;

// shared structs to prevent duplication
pub mod constraints;
pub use constraints::*;
