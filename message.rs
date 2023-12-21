//use std::collections::BTreeMap;
use std::fmt::Debug;
use crate::crypto::{Signature, SignatureShare};
//use hex_fmt::HexFmt;
use rand::distributions::{Distribution, Standard};
use rand::seq::SliceRandom;
use rand::{self, Rng};
use serde::{Deserialize, Serialize};
use crate::NodeIdT;
use crate::broadcast::merkle::Digest;

/// Message from Subset to remote nodes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Message<N: NodeIdT> {
    /// The proposer whose contribution this message is about.
    pub proposer_id: N,
    pub content: MessageContent<N>,
}

impl<N: NodeIdT> Distribution<Message<N>> for Standard
where
    Standard: Distribution<N>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message<N> {
        Message {
            proposer_id: rng.gen::<N>(),
            content: rng.gen::<MessageContent<N>>(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize,  PartialEq)]
pub enum MessageContent<N: NodeIdT> {
    /// Received `cbc_value` messages.
    Cbcvalue(Vec<(N, (Digest, Signature))>),
    /// Received `cbc_echo` messages.
    Cbcecho(SignatureShare),
    /// Received `cbc_final` message.
    Cbcfinal((Digest, Signature)),
}

impl<N: NodeIdT> Distribution<MessageContent<N>> for Standard
where
    Standard: Distribution<N>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MessageContent<N> {
        let message_type = *["Cbcvalue", "Cbcecho", "Cbcfinal"].choose(rng).unwrap();

        match message_type {
            "Cbcvalue" => {
                let mut map = Vec::new();
                let id = rng.gen::<N>();
                let digest = rng.gen::<crate::broadcast::merkle::Digest>();
                let signature = rng.gen::<crate::crypto::Signature>();
                map.push((id, (digest, signature)));
                MessageContent::Cbcvalue(map)
            },
            "Cbcecho" => {
                let signature_share = rng.gen::<crate::crypto::SignatureShare>();
                MessageContent::Cbcecho(signature_share)
            },
            "Cbcfinal" => {
                let digest = rng.gen::<crate::broadcast::merkle::Digest>();
                let signature = rng.gen::<crate::crypto::Signature>();
                MessageContent::Cbcfinal((digest, signature))
            },
            _ => unreachable!(),
        }
    }
}

// NOTE: Extending rand_derive to correctly generate random values from boxes would make this
// implementation obsolete; however at the time of this writing, `rand_derive` is already deprecated
// with no replacement in sight.
impl<N: NodeIdT> MessageContent<N> { 
    /// Returns a `Message` with this content and the specified proposer ID.
    pub(super) fn with(self, proposer_id: N) -> Message<N> {
        Message {
            proposer_id,
            content: self,
        }
    }
}
/*impl Message {
    pub fn as_send(&self) -> Option<&[u8]> {
        if let Message::CBC_SEND(ref content) = *self {
            Some(content)
        } else {
            None
        }
    }

    pub fn as_echo(&self) -> Option<(&[u8], &SignatureShare)> {
        if let Message::CBC_ECHO(ref content, ref signature) = *self {
            Some((content, signature))
        } else {
            None
        }
    }

    pub fn as_final(&self) -> Option<(&[u8], &Signature, &[(usize, Vec<u8>)])> {
        if let Message::CBC_FINAL(ref content, ref signature, ref proofs) = *self {
            Some((content, signature, proofs))
        } else {
            None
        }
    }
}*/

/*impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::CBC_SEND(ref content) => write!(f, "CBC_SEND({:?})", HexFmt(content)),
            Message::CBC_ECHO(ref content, ref signatureshare) => write!(f, "CBC_ECHO({:?}, {:?})", HexFmt(content), signatureshare),
            Message::CBC_FINAL(ref content, ref signature, ref proofs) => write!(f, "CBC_FINAL({:?}, {:?}, {:?})", HexFmt(content), signature, proofs),
        }
    }
}

/// Wrapper for a `Proof`, to print the bytes as a shortened hexadecimal number.
pub struct HexProof<'a, T>(pub &'a Proof<T>);

impl<'a, T: AsRef<[u8]>> fmt::Debug for HexProof<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Proof {{ #{}, root_hash: {:0.10}, value: {:0.10}, .. }}",
            &self.0.index(),
            HexFmt(self.0.root_hash()),
            HexFmt(self.0.value())
        )
    }
}*/
