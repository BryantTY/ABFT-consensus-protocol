//! # CBC (Correct-By-Construction) Consensus Algorithm
//!
//! The CBC Consensus Algorithm assumes a network of _N_ validators that send signed messages to
//! each other, with at most _f_ of them faulty, where _3 f < N_. It allows one validator, the
//! "leader", to propose a value to the other validators, and guarantees that:
//! * If the leader is correct, all correct validators will agree on the proposed value.
//! * If the leader is faulty, all correct validators will eventually agree on some value.
//!
//! Handling the networking and signing is the responsibility of this crate's user:
//! * The leader needs to be determined beforehand. In all nodes, `CBC::new` must be called
//! with the same leader's ID.
//! * Only in the leader, `CBC::propose` is called, with the value they want to propose.
//! * All messages contained in `Step`s returned by any of the methods must be securely sent to the
//! other nodes, e.g. by signing, (possibly encrypting) and sending them over the network.
//! * All incoming, verified messages must be passed into `CBC::handle_message`. It is the
//! user's responsibility to validate the sender, e.g. by checking the signature.
//! * Eventually, a `Step` will contain the value as its output. At that point, the algorithm has
//! terminated and the instance can be dropped. (The messages in the last step still need to be
//! sent out, though, to allow the other nodes to terminate, too.)
//!
//! This module provides the implementation for the CBC Consensus Algorithm and the messages
//! associated with it.

mod consistent_broadcast;
mod error;
//pub(crate) mod merkle;
mod message;
pub(crate) mod consistent_broadcast_set;

pub use self::consistent_broadcast::{ConsistentBroadcast, Step};
pub use self::error::{Error, FaultKind, Result};
pub use self::message::{Message, MessageContent};
pub use self::consistent_broadcast_set::ConsistentBroadcastSet;

