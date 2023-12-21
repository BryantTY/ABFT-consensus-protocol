use failure::Fail;

/// A CBC error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
    /// Number of participants must be within a valid range.
    #[fail(display = "Invalid number of participants")]
    InvalidNodeCount,
    #[fail(display = "Invalid Proposer")]
    InvalidProposer,
    /// Instance cannot propose a value unless it's the leader.
    #[fail(display = "Instance cannot propose")]
    InstanceCannotPropose,
    /// Multiple inputs received. Only a single value can be proposed.
    #[fail(display = "Multiple inputs received")]
    MultipleInputs,
    #[fail(display = " Multiple Values From Sender")]
    MultipleValuesFromSender,
    /// Unknown sender.
    #[fail(display = "Unknown sender")]
    UnknownSender,
    #[fail(display = "Unknown proposer")]
    UnknownProposer,
    #[fail(display = "No secret key")]
    Nosecretkey,
    #[fail(display = " Value Already Sent")]
    ValueAlreadySent,
    /// Failed to generate or verify threshold signature.
    #[fail(display = "Final Already Sent")]
    FinalAlreadySent,
    #[fail(display = "Final AlreadypReceived")]
    FinalAlreadyReceived,
    #[fail(display = "Already Decided")]
    AlreadyDecided,
    #[fail(display = "Multiple Consistent Broadcast Output")]
    MultipleConsistentBroadcastOutput,
}

/// A CBC result.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Represents each reason why a CBC message could be faulty.
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum FaultKind {
    /// `CBC` received a `SEND` from a node other than the leader.
    #[fail(display = "`CBC` received a `SEND` from a node other than the proposer.")]
    ReceivedValueFromNonLeader,
    #[fail(display = "Invalid Value.")]
    InvalidValue,
    #[fail(display = "Invalid Final.")]
    InvalidFinal,
    #[fail(display = "Received Value From Non Proposer.")]
    ReceivedValueFromNonProposer,
    #[fail(display = "Received Invalid Echo Message.")]
    ReceivedInvalidEchoMessage,
    /// `CBC` received multiple different `ECHO`s from the same sender.
    #[fail(display = "`CBC` received multiple different `ECHO`s from the same sender.")]
    MultipleEchos,
    /// `CBC` received multiple different `FINAL`s from the same sender.
    #[fail(display = "`CBC` received multiple different `FINAL`s from the same sender.")]
    MultipleFinals,
    /// Received a message for a different or outdated CBC instance.
    #[fail(display = "Unexpected message instance.")]
    UnexpectedInstance,
    /// Received an `ECHO` or `FINAL` with an invalid signature share.
    #[fail(display = "Invalid Signature Share.")]
    InvalidSignatureShare,
    #[fail(display = "Invalid Message Type.")]
    InvalidMessageType,
    #[fail(display = " Multiple Consistent Broadcast Output.")]
    MultipleConsistentBroadcastOutput,
    #[fail(display = "Non Proposer.")]
    NonProposer
}
