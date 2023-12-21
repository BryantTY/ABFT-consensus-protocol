use failure::Fail;

/// A CBC error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    /// Number of participants must be within a valid range.
    #[fail(display = "Invalid number of participants")]
    InvalidNodeCount,
    /// Secret key must be provided.
    #[fail(display = "No secret key")]
    Nosecretkey,
    /// Instance cannot propose a value unless it's the leader.
    #[fail(display = "Instance cannot propose")]
    InstanceCannotPropose,
    /// Multiple inputs received. Only a single value can be proposed.
    #[fail(display = "Multiple inputs received")]
    MultipleInputs,
    /// Unknown sender.
    #[fail(display = "Unknown sender")]
    UnknownSender,
    /// Failed to generate or verify threshold signature.
    #[fail(display = "Threshold signature error")]
    ThresholdSignatureError,
}

/// A CBC result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Represents each reason why a CBC message could be faulty.
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum FaultKind {
    /// `CBC` received a `SEND` from a node other than the leader.
    #[fail(display = "`LS` received a `leader_selection_message_share` from a node other than the proposer.")]
    ReceivedValueFromNonLeader,
    /// `CBC` received multiple different `SEND`s from the leader.
    #[fail(display = "`LS` received multiple different `leader_selection_message_share`s from the proposer.")]
    MultipleValues,
    /// Received a message for a different or outdated CBC instance.
    #[fail(display = "Unexpected message instance.")]
    UnexpectedInstance,
    /// Received an `ECHO` or `FINAL` with an invalid signature share.
    #[fail(display = "Invalid signature share in the message.")]
    InvalidSignatureShare,
    #[fail(display = "Invalid Epoch.")]
    InvalidEpoch
}
