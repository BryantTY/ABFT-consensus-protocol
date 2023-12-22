use std::fmt::{self, Debug};
use std::sync::Arc;
use crate::network_info::{NetworkInfo, ValidatorSet};
use hex_fmt::HexFmt;
use rand::distributions::{Distribution, Standard};
use rand::{self, seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
//use crate::threshold_sign::ThresholdSign;
use crate::crypto::SignatureShare;
use super::merkle::{Digest, MerkleTree, Proof};
use crate::threshold_sign::ThresholdSign;  // Re-enable this import.
use threshold_crypto::SecretKeySet;



/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub enum Message {
    /// A share of the value, sent from the sender to another validator.
    Value(Proof<Vec<u8>>),
    /// A copy of the value received from the sender, multicast by a validator.
    Echo(Proof<Vec<u8>>),
    //  Indicates that the sender knows that every node will eventually be able to decode.
    // revised !!!!!!
    /// ready message
    Ready(Digest),
    /// A share of the signature, sent from the sender to another validator.
    Sig(Digest, SignatureShare),
    /// Indicates that this node has enough shares to decode the message with given Merkle root.
    CanDecode(Digest),
    /// Indicates that sender can send an Echo for given Merkle root.
    EchoHash(Digest),
}

// A random generation impl is provided for test cases. Unfortunately `#[cfg(test)]` does not work
// for integration tests.
impl Distribution<Message> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Message {
        let message_type = *["value", "echo", "ready",  "signature_share", "can_decode", "echo_hash"]
            .choose(rng)
            .unwrap();

        // Create a random buffer for our proof.
        let mut buffer: [u8; 32] = [0; 32];//创建了一个32字节的缓冲区
        rng.fill_bytes(&mut buffer);//在缓冲区中随机填充内容

        // Generate a dummy proof to fill broadcast messages with.
        let tree = MerkleTree::from_vec(vec![buffer.to_vec()]);
        let proof = tree.proof(0).unwrap();
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let threshold = 1;  // 例如，假设最多有1个故障节点
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        // 生成秘密密钥共享和公钥集，这些通常是通过某种密码方案获得的，但在这里我们只是创建了随机值。
        let secret_key_share = sk_set.secret_key_share(0);  // 0是这里的索引
        //let secret_key_share = rng.gen();
        let our_id = "node1".to_string();

        // 创建一个虚拟的网络信息实例。
        let netinfo = Arc::new(NetworkInfo::new(
            our_id, Some(secret_key_share), pk_set,
            /* val_set */ ValidatorSet::from(vec!["node1".to_string(), "node2".to_string(), "node3".to_string()])
        ));

        // 使用网络信息创建阈值签名实例。
        let mut threshold_sign = ThresholdSign::new(netinfo.clone());

        // 签名一些随机数据以生成签名共享。
        let _dummy_doc: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let _step = threshold_sign.sign().expect("Failed to generate signature share");
        
        // 从ThresholdSign实例中提取生成的签名共享
        let signature_share = threshold_sign.signature_share.expect("Signature share not generated");

        
        // Create a dummy message with the dummy signature_share.
        match message_type {
            "value" => Message::Value(proof),
            "echo" => Message::Echo(proof),
            "ready" => Message::Ready([b'r'; 32]),
            "signature_share" => {Message::Sig([b'r'; 32], signature_share)},
            "can_decode" => Message::Ready([b'r'; 32]),
            "echo_hash" => Message::Ready([b'r'; 32]),
            _ => unreachable!(),
        }

        
    }
}

impl Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Value(ref v) => f.debug_tuple("Value").field(&HexProof(v)).finish(),
            Message::Echo(ref v) => f.debug_tuple("Echo").field(&HexProof(v)).finish(),
            Message::Ready(ref b) => write!(f, "Ready({:0.10})", HexFmt(b)),
            Message::CanDecode(ref b) => write!(f, "CanDecode({:0.10})", HexFmt(b)),
            Message::EchoHash(ref b) => write!(f, "EchoHash({:0.10})", HexFmt(b)),
            Message::Sig(ref d, ref s) => write!(f, "Sig({:0.10}, {:0.10})", HexFmt(d), HexFmt(&s.to_bytes())),  // 匹配两个字段
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
}
