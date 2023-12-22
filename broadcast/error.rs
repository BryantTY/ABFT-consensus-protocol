use failure::Fail;

/// A broadcast error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    /// Due to a limitation in `reed_solomon_erasure`, only up to 256 nodes are supported.
    #[fail(display = "Number of participants must be between 1 and 256")]
    InvalidNodeCount,
    /// Unknown proposer.
    #[fail(display = " Unknown Proposer")]
    UnknownProposer,
    /// Observers cannot propose a value.
    #[fail(display = "Instance cannot propose")]
    InstanceCannotPropose,
    /// Multiple inputs received. Only a single value can be proposed.
    #[fail(display = "Multiple inputs received")]
    MultipleInputs,
    /// Failed to construct a Merkle tree proof.
    #[fail(display = "Proof construction failed")]
    ProofConstructionFailed,
    /// Unknown sender.
    #[fail(display = "Unknown sender")]
    UnknownSender,
    /// the signer does not have a secret key.
    #[fail(display = "No secret key")]
    Nosecretkey,
    /// multiple values sent by one sender for one message type received
    #[fail(display = "Multiple  Value")]
    MultipleValue,
    /// more than one output received 
    #[fail(display = "Multiple Output Value Received")]
    MultipleOutputValueReceived,
    /// unexpected state
    #[fail(display = "Unexpected State")]
    UnexpectedState,
}

/// A broadcast result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Represents each reason why a broadcast message could be faulty.
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum FaultKind {
    /// `Broadcast` received a `Value` from a node other than the proposer.
    #[fail(display = "`Broadcast` received a `Value` from a node other than the proposer.")]
    ReceivedValueFromNonProposer,
    /// `Broadcast` received multiple different `Value`s from the proposer.
    #[fail(display = "`Broadcast` received multiple different `Value`s from the proposer.")]
    MultipleValues,
    /// `Broadcast` received multiple different `Echo`s from the same sender.
    #[fail(display = "`Broadcast` received multiple different `Echo`s from the same sender.")]
    MultipleEchos,
    /// `Broadcast` received multiple different `EchoHash`s from the same sender.
    #[fail(display = "`Broadcast` received multiple different `EchoHash`s from the same sender.")]
    MultipleEchoHashes,
    /// `Broadcast` received multiple different `Ready`s from the same sender.
    #[fail(display = "`Broadcast` received multiple different `Ready`s from the same sender.")]
    MultipleReadys,
    /// `Broadcast` recevied an Echo message containing an invalid proof.
    #[fail(display = "`Broadcast` recevied an Echo message containing an invalid proof.")]
    InvalidProof,
    /// `Broadcast` recevied an Ready message containing an invalid share.
    #[fail(display = "`Broadcast` recevied an Ready message containing an invalid share.")]
    InvalidShare,
    /// `Broadcast` recevied an Ready message containing an invalid readyhash.
    #[fail(display = "`Broadcast` recevied an Ready message containing an invalid readyhash.")]
    Invalidreadyhash,
    ///`Broadcast` received shards with valid proofs, that couldn't be decoded.
    #[fail(display = "`Broadcast` received shards with valid proofs, that couldn't be decoded.")]
    BroadcastDecoding,
    /// `Broadcast` received shards with valid proofs, that couldn't be decoded.
    #[fail(display = "`Broadcast` Send Values Multiple Time.")]
    SendValuesMultipleTime,
}
