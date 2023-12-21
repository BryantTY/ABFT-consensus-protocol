//use std::fmt::Debug;
use rand::{self, Rng};
use std::fmt;

//use hex_fmt::HexFmt;
use rand::distributions::{Distribution, Standard};
//use rand::self;
use serde::{Deserialize, Serialize};
use crate::crypto::SignatureShare;//cryto这个文件到底在哪



/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Message {
    /// A share of the value, sent from the sender to another validator.
    pub leader_round_id: u64,
    pub signature_share: SignatureShare,
}//可以在枚举中只创建一个文件吗

impl Distribution<Message> for Standard
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message {
        Message {
            leader_round_id: rng.gen::<u64>(),
            signature_share: rng.gen::<SignatureShare>(),
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("leader_round_id", &self.leader_round_id)
            .field("signature_share", &self.signature_share)
            .finish()
    }
}



/*#[derive(Debug)]
pub enum MessageContent {

    Sig(SignatureShare),

    Decide(bool),
}

// NOTE: Extending rand_derive to correctly generate random values from boxes would make this
// implementation obsolete; however at the time of this writing, `rand_derive` is already deprecated
// with no replacement in sight.
impl MessageContent {
    /// Returns a `Message` with this content and the specified proposer ID.
    pub(super) fn with_leader_round_id<N>(self, leader_round_id: usize) -> Message {
        Message {
            leader_round_id,
            content: self,
        }
    }
}*/
// A random generation impl is provided for test cases. Unfortunately `#[cfg(test)]` does not work
// for integration tests.
/*impl Distribution<Message> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message {
        let message_type = *["leader_selection_message_share"]
            .choose(rng)
            .unwrap();

        // Create a random buffer for our proof.
        let mut buffer: [u8; 32] = [0; 32];
        rng.fill_bytes(&mut buffer);

        // Generate a dummy proof to fill broadcast messages with.
        let tree = MerkleTree::from_vec(vec![buffer.to_vec()]);
        let proof = tree.proof(0).unwrap();

        match message_type {
            "leader_selection_message_share" => Message::leader_selection_message_share(proof),
            _ => unreachable!(),
        }
    }
}*/

/*impl Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Message:: sig_msg(ref signature) => f.debug_tuple("sig_msg").field(&HexProof(signature)).finish(),
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
