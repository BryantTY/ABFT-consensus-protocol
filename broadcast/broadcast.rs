use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::{fmt, result};

use byteorder::{BigEndian, ByteOrder};
use hex_fmt::{HexFmt, HexList};
use log::{debug, warn};
use rand::Rng;
//use rand::Rng;
use reed_solomon_erasure as rse;
use reed_solomon_erasure::{galois_8::Field as Field8, ReedSolomon};

use super::merkle::{Digest, MerkleTree, Proof};
use super::message::HexProof;
use super::{Error, FaultKind, Message, Result};
use crate::ConsensusProtocol;
use crate::fault_log::Fault;
use crate::{NodeIdT, Target, ValidatorSet, NetworkInfo};
// Add imports for threshold signature！！！需要核实
use crate::threshold_sign::ThresholdSign;
use crate::crypto::{hash_g2, Signature, SignatureShare};//cryto这个文件到底在哪

type RseResult<T> = result::Result<T, rse::Error>; //声明一个类型别名

/// Broadcast algorithm instance.
#[derive(Debug, Clone, PartialEq)] //为结构体对象赋予Debug特征 Debug: The type must be able to be printed in a human-readable format.
pub struct Broadcast<N> {
    /// Our ID. 自身ID
    // TODO: Make optional for observers?
    our_id: N,
    /// The set of validator IDs.
    val_set: Arc<ValidatorSet<N>>, //引用类型的对象指向一个范型结构体对象
    netinfo: Arc<NetworkInfo<N>>,
    /// The ID of the sending node.
    proposer_id: N,//范型类型
    /// Session identifier, to prevent replaying messages in other instances.
    //session_id: S,
    /// The Reed-Solomon erasure coding configuration.
    coding: Coding,//Coding这个类型在其他地方被定义了。需要了解一下coding是干嘛用的
    /// If we are the proposer: whether we have already sent the `Value` messages with the shards.
    value_sent: bool,
    /// Whether we have already sent `Echo` to all nodes who haven't sent `CanDecode`.
    echo_sent: bool,
    /// Whether we have already multicast `Ready`.
    ready_sent: bool,
    /// Whether we have already sent `EchoHash` to the right nodes.
    echo_hash_sent: bool,
    sig_share_sent: bool,
    /// Whether we have already sent `CanDecode` for the given hash.
    can_decode_sent: BTreeSet<Digest>,
    /// Whether we have already output a value.
    decided: bool,
    /// Number of faulty nodes to optimize performance for.
    // TODO: Make this configurable: Allow numbers between 0 and N/3?
    fault_estimate: usize,
    /// The hashes and proofs we have received via `Echo` and `EchoHash` messages, by sender ID.
    echos: BTreeMap<N, EchoContent>,
    /// The hashes we have received from nodes via `CanDecode` messages, by hash.
    /// A node can receive conflicting `CanDecode`s from the same node.
    can_decodes: BTreeMap<Digest, BTreeSet<N>>,
    /// Modified to include threshold signatures with root hashes.！！！！！！（后续需要核实）
    readys: BTreeMap<N, Digest>,
    signature_shares: BTreeMap<N, SignatureShare>,
    temporary_signature_shares: BTreeMap<N, SignatureShare>,
    thresholdsignature: Option<(N, (Digest, Signature))>,
    output: Option<(N, (Digest, Signature, Vec<u8>))>,
    sub_block: Vec<u8>,
}

/// A `Broadcast` step, containing at most one output.
pub type Step<N> = crate::Step<Message, (N, (Digest, Signature, Vec<u8>)), N, FaultKind>;

impl<N: NodeIdT> ConsensusProtocol for Broadcast<N> {
    type NodeId = N;
    type Input  = Vec<u8>;  // 提供的RBC实例的输入信息
    type Output = (N, (Digest, Signature, Vec<u8>)); // bc_signature
    type Message = Message; //需要对消息类型进行修改
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, _rng: &mut R) -> Result<Step<N>> {
        self.broadcast(input)
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        message: Message,
        _rng: &mut R,
    ) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    fn terminated(&self) -> bool {
        self.decided
    }

    fn our_id(&self) -> &Self::NodeId {
        //&self.our_id
        &self.our_id
    }
}

impl<N: NodeIdT> Broadcast<N> {
    /// Creates a new broadcast instance to be used by node `our_id` which expects a value proposal
    /// from node `proposer_id`.
    pub fn new<V>(our_id: N, val_set: V, netinfo: Arc<NetworkInfo<N>>, proposer_id: N) -> Result<Self>
    where
        V: Into<Arc<ValidatorSet<N>>>,//表示一个约束条件：V必须满足V的类型可以转换为Arc<ValidatorSet<N>>类型这一特征
    {
        let val_set: Arc<ValidatorSet<N>> = val_set.into();
        let parity_shard_num = 2 * val_set.num_faulty();
        let data_shard_num = val_set.num() - parity_shard_num;
        let coding =
            Coding::new(data_shard_num, parity_shard_num).map_err(|_| Error::InvalidNodeCount)?;
        let fault_estimate = val_set.num_faulty();

        Ok(Broadcast {
            our_id,
            val_set,
            netinfo,
            proposer_id,
            coding,
            value_sent: false,
            echo_sent: false,
            ready_sent: false,
            echo_hash_sent: false,
            sig_share_sent: false,
            can_decode_sent: BTreeSet::new(),
            decided: false,
            fault_estimate,
            echos: BTreeMap::new(),
            can_decodes: BTreeMap::new(),
            readys: BTreeMap::new(),
            signature_shares: BTreeMap::new(),
            temporary_signature_shares: BTreeMap::new(),
            output: None,
            thresholdsignature: None,
            sub_block: Vec::new(),
        })
    }
    //！！！！后续需要核实
    /*fn start_new_epoch(&mut self) {
        // ... 其他开始新epoch的逻辑 ...
    
        for value in self.epoch_signatures.values_mut() {
            *value = None;
        }
    }*/

    /// Initiates the broadcast. This must only be called in the proposer node.
    pub fn broadcast(&mut self, input: Vec<u8>) -> Result<Step<N>> {
        //如果运行这个代码的节点不是验证节点且不是本节点，就会报错
        if self.our_id != self.proposer_id {
            return Err(Error::InstanceCannotPropose);
        }
        //一个节点在一个epoch的实例中只能broadcast一次
        if self.value_sent {
            return Err(Error::MultipleInputs);
        }
        self.value_sent = true;
        // Split the value into chunks/shards, encode them with erasure codes.
        // Assemble a Merkle tree from data and parity shards. Take all proofs
        // from this tree and send them, each to its own node.
        let (proof, step) = self.send_shards(input)?;
        let our_id = &self.our_id.clone();
        Ok(step.join(self.handle_value(our_id, proof)?))//在本地对发送给自己的子块碎片也验证一遍
    }
    //最终，运行完broadcast方法后，会将运行结果填写入step结构体中。step结构体中有3个元素：output，fault_log, messages,因此，运行结果将会是这3个值中的其中之1，or2,or3

    /// Handles a message received from `sender_id`.
    ///
    /// This must be called with every message we receive from another node.
    pub fn handle_message(&mut self, sender_id: &N, message: Message) -> Result<Step<N>> {
        if !self.val_set.contains(sender_id) {
            return Err(Error::UnknownSender);
        }
        match message {
            Message::Value(p) => self.handle_value(sender_id, p),
            Message::Echo(p) => self.handle_echo(sender_id.clone(), p),
            Message::Ready(ref hash) => self.handle_ready(sender_id, hash),//！！！（后续需要核实）
            Message::Sig(ref hash, ref signatureshare) => self.handle_signature_share(&sender_id, &hash, signatureshare.clone()),//需要在message中添加内容
            Message::CanDecode(ref hash) => self.handle_can_decode(sender_id.clone(), hash.clone()),
            Message::EchoHash(ref hash) => self.handle_echo_hash(sender_id.clone(), hash.clone()),
        }
    }

    /// Returns the proposer's node ID.
    pub fn proposer_id(&self) -> &N {
        &self.proposer_id
    }

    /// Returns the set of all validator IDs.
    pub fn validator_set(&self) -> &Arc<ValidatorSet<N>> {
        &self.val_set
    }

    /// Breaks the input value into shards of equal length and encodes them --
    /// and some extra parity shards -- with a Reed-Solomon erasure coding
    /// scheme. The returned value contains the shard assigned to this
    /// node. That shard doesn't need to be sent anywhere. It gets recorded in
    /// the broadcast instance.
    fn send_shards(&mut self, mut value: Vec<u8>) -> Result<(Proof<Vec<u8>>, Step<N>)> {
        let data_shard_num = self.coding.data_shard_count();
        let parity_shard_num = self.coding.parity_shard_count();

        // Insert the length of `v` so it can be decoded without the padding.!!!!!!!!!!!!!
        let payload_len = value.len() as u32;
        value.splice(0..0, 0..4); // Insert four bytes at the beginning.
        BigEndian::write_u32(&mut value[..4], payload_len); // Write the size.
        let value_len = value.len(); // This is at least 4 now, due to the payload length.

        // Size of a Merkle tree leaf value: the value size divided by the number of data shards,
        // and rounded up, so that the full value always fits in the data shards. Always at least 1.
        let shard_len = (value_len + data_shard_num - 1) / data_shard_num;
        // Pad the last data shard with zeros. Fill the parity shards with zeros.
        value.resize(shard_len * (data_shard_num + parity_shard_num), 0);

        // Divide the vector into chunks/shards.
        let shards_iter = value.chunks_mut(shard_len);
        // Convert the iterator over slices into a vector of slices.
        let mut shards: Vec<&mut [u8]> = shards_iter.collect(); 

        // Construct the parity chunks/shards. This only fails if a shard is empty or the shards
        // have different sizes. Our shards all have size `shard_len`, which is at least 1.
        self.coding.encode(&mut shards).expect("wrong shard size");

        debug!(
            "{}: Value: {} bytes, {} per shard. Shards: {:0.10}",
            self,
            value_len,
            shard_len,
            HexList(&shards)
        );

        // Create a Merkle tree from the shards.
        let mtree = MerkleTree::from_vec(shards.into_iter().map(|shard| shard.to_vec()).collect());

        // Default result in case of `proof` error.
        let mut result = Err(Error::ProofConstructionFailed);
        assert_eq!(self.val_set.num(), mtree.values().len());

        let mut step = Step::default();
        // Send each proof to a node.
        for (id, index) in self.val_set.all_indices() {
            let proof = mtree.proof(*index).ok_or(Error::ProofConstructionFailed)?;
            if *id == self.our_id {
                // The proof is addressed to this node.
                result = Ok(proof);
            } else {
                // Rest of the proofs are sent to remote nodes.
                let msg = Target::node(id.clone()).message(Message::Value(proof));
                step.messages.push(msg);
            }
        }

        result.map(|proof| (proof, step))
    }

    /// Handles a received echo and verifies the proof it contains.
    fn handle_value(&mut self, sender_id: &N, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        // If the sender is not the proposer or if this is not the first `Value`, ignore.
        if *sender_id != self.proposer_id {
            let fault_kind = FaultKind::ReceivedValueFromNonProposer;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }//步骤返回错误，将错误结果写入步骤中。

        match self.echos.get(&self.our_id) {
            // Multiple values from proposer.执行Some(val)以尝试模式匹配。如果模式匹配成功，接着执行val.hash() != p.root_hash()。
            // Some(val)是枚举类型中的一个值，none是另一个值。
            // get() 方法通常返回一个 Option 类型，这是一个 Rust 的标准枚举类型，含有 Some(T) 和 None 两个值。
            // get() 方法接受一个键作为参数，并尝试在 HashMap 中找到与该键关联的值。如果找到，它返回 Some(value)，其中 value 是与给定键关联的值。如果没有找到，它返回 None。
            Some(val) if val.hash() != p.root_hash() => {//用p.root_hash()来提取 Proof<Vec<u8>>中的root_hash
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleValues).into())
            }////步骤返回错误，将错误结果写入步骤中。如果返回了值，就对比值是否不想等
            // Already received proof.这里检查这个方过来的p是否在之前已经发送过
            Some(EchoContent::Full(proof)) if *proof == p => {
                warn!(
                    "Node {:?} received Value({:?}) multiple times from {:?}.",
                    self.our_id,
                    HexProof(&p),
                    sender_id
                );
                return Ok(Step::default());
            }
            _ => (),
        };

        // If the proof is invalid, log the faulty node behavior and ignore.
        if !self.validate_proof(&p, &self.our_id) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidProof).into());
        }

        // Send the proof in an `Echo` message to left nodes
        // and `EchoHash` message to right nodes and handle the response.
        let echo_hash_steps = self.send_echo_hash(p.root_hash())?;
        let echo_steps = self.send_echo_left(p)?;
        Ok(echo_steps.join(echo_hash_steps))//同时去执行send_echo_hash方法和send_echo_left方法，并把这两个方法的输出结果作为这个方法的输出结果
    }

    /// Handles a received `Echo` message.
    fn handle_echo(&mut self, sender_id: N, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        // If the sender has already sent `Echo`, ignore.
        if let Some(EchoContent::Full(old_p)) = self.echos.get(&sender_id) {
            if *old_p == p {
                warn!(
                    "Node {:?} received Echo({:?}) multiple times from {:?}.",
                    self.our_id,
                    HexProof(&p),
                    sender_id,
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchos).into());
            }
        }

        // Case where we have received an earlier `EchoHash`
        // message from sender_id with different root_hash.
        if let Some(EchoContent::Hash(hash)) = self.echos.get(&sender_id) {
            if hash != p.root_hash() {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchos).into());
            }
        }

        // If the proof is invalid, log the faulty-node behavior, and ignore.
        if !self.validate_proof(&p, &sender_id) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidProof).into());
        }

        let hash = *p.root_hash();

        // Save the proof for reconstructing the tree later.
        self.echos.insert(sender_id.clone(), EchoContent::Full(p));

        let mut step = Step::default();

        //在这里需要增加一个检查，检查self.temporary_signature_shares中的键sender_id所对应的值是否存在一个signature_share，如果存在，则调用方法check_sig_share（这个方法还没有定义需要定义）
        if let Some(sig_share) = self.temporary_signature_shares.get(&sender_id) {
            if self.is_valid_sig_share(&sender_id, &hash, &sig_share.clone()) {
                self.signature_shares.insert(sender_id.clone(), sig_share.clone());
              //将  self.temporary_signature_shares的键值对（sender_id，sig_share）从temporary_signature_shares中删除掉
                self.temporary_signature_shares.remove(&sender_id);
            }
        }

        // Upon receiving `N - 2f` `Echo`s with this root hash, send `CanDecode`
        if !self.can_decode_sent.contains(&hash)
            && self.count_echos_full(&hash) >= self.coding.data_shard_count()
        {
            step.extend(self.send_can_decode(&hash)?);
        }

        // Upon receiving `N - f` `Echo`s with this root hash, multicast `Ready`.
        if !self.ready_sent && self.count_echos(&hash) >= self.val_set.num_correct() {
            step.extend(self.send_ready(&hash)?);
        }

        // Computes output if we have required number of `Echo`s and `Ready`s
        // Else returns Step::default()
        if self.ready_sent {
            step.extend(self.compute_output(&hash)?);
        }
        Ok(step)
    }

    
    fn handle_echo_hash(&mut self, sender_id: N, hash: Digest) -> Result<Step<N>> {
        // If the sender has already sent `EchoHash`, ignore.
        let step = Step::default();
        if let Some(EchoContent::Hash(old_hash)) = self.echos.get(&sender_id) {
            if old_hash == &hash {
                warn!(
                    "Node {:?} received EchoHash({:?}) multiple times from {:?}.",
                    self.our_id,
                    hash,
                    sender_id,
                );
                return Ok(step);
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchoHashes).into());
            }
        }

        // If the sender has already sent an `Echo` for the same hash, ignore.
        if let Some(EchoContent::Full(p)) = self.echos.get(&sender_id) {
            if p.root_hash() == &hash {
                return Ok(step);
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleEchoHashes).into());
            }
        }
        // Save the hash for counting later.
        self.echos
            .insert(sender_id.clone(), EchoContent::Hash(hash));

        if let Some(sig_share) = self.temporary_signature_shares.get(&sender_id) {
            if self.is_valid_sig_share(&sender_id, &hash, &sig_share.clone()) {
                self.signature_shares.insert(sender_id.clone(), sig_share.clone());
              //将  self.temporary_signature_shares的键值对（sender_id，sig_share）从temporary_signature_shares中删除掉
                self.temporary_signature_shares.remove(&sender_id);
            }
        }

        if self.ready_sent || self.count_echos(&hash) < self.val_set.num_correct() {
            return self.compute_output(&hash);
        }
        // Upon receiving `N - f` `Echo`s with this root hash, multicast `Ready`.
        self.send_ready(&hash)
    }

    /// Handles a received `CanDecode` message.
    fn handle_can_decode(&mut self, sender_id: N, hash: Digest) -> Result<Step<N>> {
        // Save the hash for counting later. If hash from sender_id already exists, emit a warning.
        let step = Step::default();
        if let Some(nodes) = self.can_decodes.get(&hash) {
            if nodes.contains(&sender_id) {
                warn!(
                    "Node {:?} received same CanDecode({:?}) multiple times from {:?}.",
                    self.our_id,
                    hash,
                    sender_id,
                );
            }
        }
        self.can_decodes
            .entry(hash)
            .or_default()
            .insert(sender_id.clone());
        
        if let Some(sig_share) = self.temporary_signature_shares.get(&sender_id) {
            if self.is_valid_sig_share(&sender_id, &hash, &sig_share.clone()) {
                self.signature_shares.insert(sender_id.clone(), sig_share.clone());
              //将  self.temporary_signature_shares的键值对（sender_id，sig_share）从temporary_signature_shares中删除掉
                self.temporary_signature_shares.remove(&sender_id);
            }
        }
        Ok(step)
    }

    /// Handles a received `Ready` message with a threshold signature share.！！！需要核实signature_share: &SignatureShare
    fn handle_ready(&mut self, sender_id: &N, hash: &Digest) -> Result<Step<N>> {

        // If the sender has already sent a `Ready` before, ignore.
        if let Some(old_hash) = self.readys.get(sender_id) {//数据结构变了这么写还对吗
            if old_hash == hash {
                warn!(
                    "Node {:?} received Ready({:?}) multiple times from {:?}.",
                    self.our_id,
                    hash,
                    sender_id
                );
                return Ok(Step::default());//是否可以理解为结构体数据不变
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleReadys).into());
            }
        }

        // Store the received Ready message and its signature share.
        self.readys.insert(sender_id.clone(), hash.clone());

        let mut step = Step::default();
        // Upon receiving f + 1 matching Ready(h) messages, if Ready
        // has not yet been sent, multicast Ready(h) with the threshold signature share.
        if self.count_readys(hash) == self.val_set.num_faulty() + 1 && !self.ready_sent {
            // Enqueue a broadcast of a Ready message.
            let ready_step = self.send_ready(hash)?;
            //let sig_share_step = self.send_signatuer_share(hash)?;///这个地方需要做一个合并
            step = step.join(ready_step);
        }
        // Upon receiving 2f + 1 matching Ready(h) messages, send full
        // `Echo` message to every node who hasn't sent us a `CanDecode`
        if self.count_readys(hash) == 2 * self.val_set.num_faulty() + 1 {
            step.extend(self.send_echo_remaining(hash)?);
        }

        Ok(step.join(self.compute_output(hash)?))
    }
      
    /// Handles a `ThresholdSign` message. If there is output, starts the next epoch. The function
    /// may output a decision value.
    fn handle_signature_share(&mut self, sender_id: &N, root_hash: &Digest, sig_share: SignatureShare) -> Result<Step<N>> {
        let mut step: crate::Step<Message, (N, ([u8; 32], Signature, Vec<u8>)), N, FaultKind> = Step::default();
        
        if !self.val_set.contains(&sender_id) {
            return Err(Error::UnknownSender);
        }
    
        if let Some(_sig_share) = self.signature_shares.get(&sender_id) {
            warn!("Node {:?} received signature_share multiple times from {:?}.", self.our_id, sender_id);
            return Ok(step);
        }

        //let mut root_hash: Option<Digest> = None; // Initialize a variable to hold the hash.

        if let Some(echo_content) = self.echos.get(&sender_id) {
            let hash: Option<[u8; 32]> = Some(echo_content.hash().clone());
            let unwrapped_hash = hash.unwrap();
            if unwrapped_hash == root_hash.clone() {
                if self.is_valid_sig_share(&sender_id, &unwrapped_hash.clone(), &sig_share) {
                    self.signature_shares.insert(sender_id.clone(), sig_share.clone());
                    if let Some(_sig_share) = self.temporary_signature_shares.get(&sender_id) {
                        self.temporary_signature_shares.remove(&sender_id);
                    }
                } else {
                    return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidShare).into());
                }
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidShare).into());
            }
        } else if let Some(digest) = self.readys.get(&sender_id) {
            let hash = Some(digest.clone());
            let unwrapped_hash = hash.unwrap();
            if unwrapped_hash == root_hash.clone() {
                if self.is_valid_sig_share(&sender_id, &unwrapped_hash, &sig_share) {
                    self.signature_shares.insert(sender_id.clone(), sig_share.clone());
                    if let Some(_sig_share) = self.temporary_signature_shares.get(&sender_id) {
                        self.temporary_signature_shares.remove(&sender_id);
                    }
                } else {
                    return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidShare).into());
                }
            }
            else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidShare).into());
            }
        } else if self.can_decodes.values().any(|set| set.contains(&sender_id)) {
            for (digest, set) in &self.can_decodes {
                if set.contains(&sender_id) {
                    // Move this block of code before the `break`.
                    if digest.clone() == root_hash.clone() {
                        if self.is_valid_sig_share(&sender_id, &root_hash, &sig_share) {
                            self.signature_shares.insert(sender_id.clone(), sig_share.clone());
                            if let Some(_sig_share) = self.temporary_signature_shares.get(&sender_id) {
                                self.temporary_signature_shares.remove(&sender_id);
                            }
                        } else {
                            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidShare).into());
                        }
                    }
                    break; 
                } else {
                    return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidShare).into());
                }
            }
        } else {
            self.temporary_signature_shares.insert(sender_id.clone(), sig_share.clone());
            return Ok(step); // Early return, since no relevant hash was found.
        }

        if self.count_signature_shares(&sig_share) == self.val_set.num_faulty() + 1 && !self.ready_sent {
            // Enqueue a broadcast of a Ready message.
            step = step.join(self.send_ready(&root_hash)?);
           
            //step = step.join(self.send_signature_share(root_hash)?)///combine!!!!!!!!!!!!!!
        }

        if self.count_signature_shares(&sig_share) == 2 * self.val_set.num_faulty() + 1  {
            let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));
            ts.doc_hash = Some(hash_g2(root_hash));
            let unwrapped_doc_hash = ts.doc_hash.unwrap();
            let threshold_signature = ts.combine_and_verify_sig(unwrapped_doc_hash).expect("Signature not generated");
            self.thresholdsignature = Some((sender_id.clone(), (root_hash.clone(), threshold_signature.clone())));
            step = step.join(self.try_output()?);         
        }
        Ok(step)
    }
    /// Checks if the given signature share is valid for the specified sender and hash.
    ///
    /// # Parameters
    /// * `sender_id` - The ID of the sender.
    /// * `hash` - The hash of the document.
    /// * `signature_share` - The signature share to verify.
    ///
    /// # Returns
    /// Returns `true` if the signature share is valid, otherwise returns `false`.
    pub fn is_valid_sig_share(&self, sender_id: &N, hash: &Digest, signature_share: &SignatureShare) -> bool {
        let mut ts = ThresholdSign::new(self.netinfo.clone());
    
        // Set the document hash
        ts.doc_hash = Some(hash_g2(hash));
    
        ts.is_share_valid(&sender_id, &signature_share)
    } 

    /// Sends `Echo` message to all left nodes and handles it.
    fn send_echo_left(&mut self, p: Proof<Vec<u8>>) -> Result<Step<N>> {
        //运行该实例的节点必须是验证节点组中的一员
        if !self.val_set.contains(&self.our_id) {
            return Ok(Step::default());//实例的状态不会有任何更新
        }
        let echo_msg = Message::Echo(p.clone());
        let mut step = Step::default();
        let right = self.right_nodes().cloned().collect();//节点id编号在自己右侧的节点全部挑选出来
        // Send `Echo` message to all non-validating nodes and the ones on our left.
        let msg = Target::AllExcept(right).message(echo_msg);//将消息发送给处了在自己右侧节点外的所有节点
        step.messages.push(msg);//将上一步的行为记录在step的message中（更新了step中的状态）
        let our_id = &self.our_id.clone();
        Ok(step.join(self.handle_echo(our_id.clone(), p)?))//因为消息也发送给了自己，所以自己也要验证一遍
    }

    /// Sends `Echo` message to remaining nodes who haven't sent `CanDecode`
    fn send_echo_remaining(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.echo_sent = true;
        if !self.val_set.contains(&self.our_id) {
            return Ok(Step::default());
        }

        let p = match self.echos.get(&self.our_id) {
            // Haven't received `Echo`.
            None | Some(EchoContent::Hash(_)) => return Ok(Step::default()),
            // Received `Echo` for different hash.
            Some(EchoContent::Full(p)) if p.root_hash() != hash => return Ok(Step::default()),
            Some(EchoContent::Full(p)) => p.clone(),
        };

        let echo_msg = Message::Echo(p);
        let mut step = Step::default();

        let senders = self.can_decodes.get(hash);
        let right = self
            .right_nodes()
            .filter(|id| senders.map_or(true, |s| !s.contains(id)))
            .cloned()
            .collect();
        step.messages.push(Target::Nodes(right).message(echo_msg));//广播的消息需要记录在step的message中
        Ok(step)
    }

    /// Sends an `EchoHash` message and handles it. Does nothing if we are only an observer.
    fn send_echo_hash(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.echo_hash_sent = true;
        if !self.val_set.contains(&self.our_id) {
            return Ok(Step::default());
        }//这个地方涉及一个逻辑，如果节点不在验证组中，他就永远不会在发送echo_hash消息了
        let echo_hash_msg = Message::EchoHash(*hash);
        let mut step = Step::default();
        let right = self.right_nodes().cloned().collect();
        let msg = Target::Nodes(right).message(echo_hash_msg);//可视化这个步骤
        step.messages.push(msg);
        let our_id = &self.our_id.clone();
        Ok(step.join(self.handle_echo_hash(our_id.clone(), hash.clone())?))//并没有将send_echo_hash发送给自己
    }

    /// Returns an iterator over all nodes to our right.
    ///
    /// The nodes are arranged in a circle according to their ID, starting with our own. The first
    /// _N - 2 f + g_ nodes are considered "to our left" and the rest "to our right".
    ///
    /// These are the nodes to which we only send an `EchoHash` message in the beginning.
    fn right_nodes(&self) -> impl Iterator<Item = &N> {
        let our_id = self.our_id.clone();
        let not_us = move |x: &&N| **x != our_id;
        self.val_set
            .all_ids()
            .cycle()
            .skip_while(not_us.clone())
            .skip(self.val_set.num_correct() - self.val_set.num_faulty() + self.fault_estimate)
            .take_while(not_us)
    }

    /// Sends a `CanDecode` message and handles it. Does nothing if we are only an observer.
    fn send_can_decode(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.can_decode_sent.insert(hash.clone());
        if !self.val_set.contains(&self.our_id) {
            return Ok(Step::default());
        }

        let can_decode_msg = Message::CanDecode(*hash);
        let mut step = Step::default();

        let our_id = &self.our_id.clone();
        let recipients = self
            .val_set
            .all_ids()
            .filter(|id| match self.echos.get(id) {
                Some(EchoContent::Hash(_)) | None => *id != our_id,
                _ => false,
            })
            .cloned()
            .collect();
        let msg = Target::Nodes(recipients).message(can_decode_msg);
        step.messages.push(msg);
        Ok(step.join(self.handle_can_decode(our_id.clone(), hash.clone())?))
    }

    /// Sends a `Ready` message and handles it. Does nothing if we are only an observer.
    fn send_ready(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.ready_sent = true;
        if !self.val_set.contains(&self.our_id) {
            return Ok(Step::default());
        }
        let ready_msg = Message::Ready(*hash);
        //let mut step: crate::Step<Message, (N, ([u8; 32], Signature, Vec<u8>)), N, FaultKind> = Step::default();
        let mut step: crate::Step<Message, (N, ([u8; 32], Signature, Vec<u8>)), N, FaultKind> =Target::all().message(ready_msg).into();
        step = step.join(self.send_signature_share(hash)?);
        let our_id = &self.our_id.clone();
        step = step.join(self.handle_ready(our_id, hash)?);
        Ok(step)
    }

    fn send_signature_share(&mut self, hash: &Digest) -> Result<Step<N>> {
        self.sig_share_sent = true;
        let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo.clone()));
    
        // Set the document hash
        ts.doc_hash = Some(hash_g2(hash)); 
        // Generate the signature share and also broadcast it
        let _ts_sign_result = ts.sign();
        let signature_share = ts.signature_share.expect("Signature share not generated");
        let sig_msg = (hash.clone(), signature_share.clone());
        let mut step: crate::Step<Message, (N, ([u8; 32], Signature, Vec<u8>)), N, FaultKind> = Step::default();
        let _indices: Vec<_> = self.val_set.all_indices()
                                    .map(|(id, index)| (id.clone(), *index))
                                    .collect();
        let _our_id_clone = self.our_id.clone();
        //let _sig_msg_clone = (sig_msg.0.clone(), sig_msg.1.clone());

        for (id, _index) in _indices {
            if &id.clone() == &self.our_id.clone() {
                // The proof is addressed to this node.
                //let (hash_part, signature_share) = sig_msg;
                step = step.join(self.handle_signature_share(&_our_id_clone, &sig_msg.0.clone(), sig_msg.1.clone())?);
            } else {
                // Rest of the proofs are sent to remote nodes.
                //let (hash_part, signature_share_part) = sig_msg;
                let msg: crate::TargetedMessage<Message, N> = Target::node(id.clone()).message(Message::Sig(sig_msg.0.clone(), sig_msg.1.clone()));
                step.messages.push(msg);
            }
        }
        //step = Target::all().message(sig_msg).into();
        return Ok(step);
    }


        
        // If you wish to extract the SignatureShare for additional processing, you can do so here.
        /*match ts_sign_result {
            Ok(ts_step) => {
            // ... (Same as previous code)
    
                // Extract the msg from ts_step
                let message_target_option = ts_step.messages.first();
                if let Some(message_target) = ts_step.messages.first() {  // Assuming messages is a Vec
                    let msg = &message_target.message;
                    let sig_msg = (msg.clone(), ts.doc_hash.clone());
                    let mut new_step = Step::default();
                    let targeted_message = Target::all().message(sig_msg);
                    new_step.messages.push(targeted_message);
                    step = step.join(new_step);
                    //step = Target::all().message(sig_msg).into();
                    //这一步需要修改，只发送给proposer,需要在Target下修改
                    step = step.join(self.handle_threshold_signature(self.our_id, &hash.clone(), msg)?);
                    return Ok(step);
                }
            }
            Err(_) => Err(Error::Nosecretkey)
        }*/    
//这段代码需要进一步核实！！！！！！！！！！！！！！


    fn compute_output(&mut self, hash: &Digest) -> Result<Step<N>> {
        if self.decided
            || self.count_readys(hash) <= 2 * self.val_set.num_faulty()
            || self.count_echos_full(hash) < self.coding.data_shard_count()
        {
            return Ok(Step::default());
        }
        let step = Step::default();
        // Upon receiving 2f + 1 matching Ready(h) messages, wait for N − 2f Echo messages.
        let mut leaf_values: Vec<Option<Box<[u8]>>> = self
            .val_set
            .all_ids()
            .map(|id| {
                self.echos
                    .get(id)
                    .and_then(EchoContent::proof)
                    .and_then(|p| {
                        if p.root_hash() == hash {
                            Some(p.value().clone().into_boxed_slice())
                        } else {
                            None
                        }
                    })
            })
            .collect();
        if let Some(value) = self.decode_from_shards(&mut leaf_values, hash) {
            self.decided = true;
            self.sub_block = value;
            
            // 解构 Result
            let new_step = self.try_output()?;
            
            // Join steps
            Ok(step.join(new_step))
        } else {
            let fault_kind = FaultKind::BroadcastDecoding;
            Ok(Fault::new(self.proposer_id.clone(), fault_kind).into())
        }
    }///需要在上一层的结构体中，增加一个数组，记录每一个bc实例是否输出了decided。

    pub fn try_output(&mut self) -> Result<Step<N>> {

        let mut step: crate::Step<Message, (N, ([u8; 32], Signature, Vec<u8>)), N, FaultKind> = Step::default();
        //如果self.thresholdsignature有值且self.sub_block有值且self.output为None值，则将self.thresholdsignature的值和self.sub_block的值赋值给self.output
        //否则，执行Ok(step)
        if self.thresholdsignature.is_some() && !self.sub_block.is_empty() && self.output.is_none() {
            // 解构 self.thresholdsignature 和 self.sub_block 的值
            if let Some((id, (digest, signature))) = &self.thresholdsignature {
                // 将 self.thresholdsignature 和 self.sub_block 的值赋给 self.output
                self.output = Some((id.clone(), (digest.clone(), signature.clone(), self.sub_block.clone())));
                if let Some(output) = &self.output {
                    let output_clone = output.clone();
                    step = step.with_output(output_clone);
                } else {
                    // 这一分支应当永远不会执行，因为我们已经检查了 self.thresholdsignature 是 Some
                    return Err(Error::UnexpectedState);
                }
            } else {
                // 这一分支应当永远不会执行，因为我们已经检查了 self.thresholdsignature 是 Some
                return Err(Error::UnexpectedState);
            }     
        }
        Ok(step)
    }


    /// Interpolates the missing shards and glues together the data shards to retrieve the value.
    /// This returns `None` if reconstruction failed or the reconstructed shards don't match the
    /// root hash. This can only happen if the proposer provided invalid shards.
    fn decode_from_shards(
        &self,
        leaf_values: &mut [Option<Box<[u8]>>],
        root_hash: &Digest,
    ) -> Option<Vec<u8>> {
        // Try to interpolate the Merkle tree using the Reed-Solomon erasure coding scheme.
        self.coding.reconstruct_shards(leaf_values).ok()?;

        // Collect shards for tree construction.
        let shards: Vec<Vec<u8>> = leaf_values
            .iter()
            .filter_map(|l| l.as_ref().map(|v| v.to_vec()))
            .collect();

        debug!("{}: Reconstructed shards: {:0.10}", self, HexList(&shards));

        // Construct the Merkle tree.
        let mtree = MerkleTree::from_vec(shards);
        // If the root hash of the reconstructed tree does not match the one
        // received with proofs then abort.
        if mtree.root_hash() != root_hash {
            return None; // The proposer is faulty.
        }

        // Reconstruct the value from the data shards:
        // Concatenate the leaf values that are data shards The first four bytes are
        // interpreted as the payload size, and the padding beyond that size is dropped.
        let count = self.coding.data_shard_count();
        let mut bytes = mtree.into_values().into_iter().take(count).flatten();
        let payload_len = match (bytes.next(), bytes.next(), bytes.next(), bytes.next()) {
            (Some(b0), Some(b1), Some(b2), Some(b3)) => {
                BigEndian::read_u32(&[b0, b1, b2, b3]) as usize
            }
            _ => return None, // The proposer is faulty: no payload size.
        };
        let payload: Vec<u8> = bytes.take(payload_len).collect();
        debug!("{}: Glued data shards {:0.10}", self, HexFmt(&payload));
        Some(payload)
    }

    /// Returns `true` if the proof is valid and has the same index as the node ID.
    fn validate_proof(&self, p: &Proof<Vec<u8>>, id: &N) -> bool {
        self.val_set.index(id) == Some(p.index()) && p.validate(self.val_set.num())
    }

    /// Returns the number of nodes that have sent us a full `Echo` message with this hash.
    fn count_echos_full(&self, hash: &Digest) -> usize {
        self.echos
            .values()
            .filter_map(EchoContent::proof)
            .filter(|p| p.root_hash() == hash)
            .count()
    }

    /// Returns the number of nodes that have sent us an `Echo` or `EchoHash` message with this hash.
    fn count_echos(&self, hash: &Digest) -> usize {
        self.echos.values().filter(|v| v.hash() == hash).count()
    }

    /// Returns the number of nodes that have sent us a `Ready` message with this hash.
    fn count_readys(&self, hash: &Digest) -> usize {
        self.readys
            .values()
            .filter(|h| h.as_slice() == hash)
            .count()
    }

    fn count_signature_shares(&self, target_signature_share: &SignatureShare) -> usize {
        self.signature_shares
            .values()
            .filter(|signature_share| *signature_share == target_signature_share)
            .count()
    }    

}

impl<N: NodeIdT> fmt::Display for Broadcast<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> result::Result<(), fmt::Error> {
        write!(f, "{:?} Broadcast({:?})", self.our_id, self.proposer_id)
    }
}

/// A wrapper for `ReedSolomon` that doesn't panic if there are no parity shards.
#[derive(Debug, Clone, PartialEq)]
enum Coding {
    /// A `ReedSolomon` instance with at least one parity shard.
    ReedSolomon(Box<ReedSolomon<Field8>>),
    /// A no-op replacement that doesn't encode or decode anything.
    Trivial(usize),
}

impl Coding {
    /// Creates a new `Coding` instance with the given number of shards.
    fn new(data_shard_num: usize, parity_shard_num: usize) -> RseResult<Self> {
        Ok(if parity_shard_num > 0 {
            let rs = ReedSolomon::new(data_shard_num, parity_shard_num)?;
            Coding::ReedSolomon(Box::new(rs))
        } else {
            Coding::Trivial(data_shard_num)
        })
    }

    /// Returns the number of data shards.
    fn data_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.data_shard_count(),
            Coding::Trivial(dsc) => dsc,
        }
    }

    /// Returns the number of parity shards.
    fn parity_shard_count(&self) -> usize {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.parity_shard_count(),
            Coding::Trivial(_) => 0,
        }
    }

    /// Constructs (and overwrites) the parity shards.
    fn encode(&self, slices: &mut [&mut [u8]]) -> RseResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.encode(slices),
            Coding::Trivial(_) => Ok(()),
        }
    }

    /// If enough shards are present, reconstructs the missing ones.
    fn reconstruct_shards(&self, shards: &mut [Option<Box<[u8]>>]) -> RseResult<()> {
        match *self {
            Coding::ReedSolomon(ref rs) => rs.reconstruct(shards),
            Coding::Trivial(_) => {
                if shards.iter().all(Option::is_some) {
                    Ok(())
                } else {
                    Err(rse::Error::TooFewShardsPresent)
                }
            }
        }
    }
}

/// Content for `EchoHash` and `Echo` messages.
#[derive(Debug, Clone, PartialEq)]
enum EchoContent {
    /// `EchoHash` message.
    Hash(Digest),
    /// `Echo` message
    Full(Proof<Vec<u8>>),
}

impl EchoContent {
    /// Returns hash of the message from either message types.
    pub fn hash(&self) -> &Digest {
        match &self {
            EchoContent::Hash(h) => h,
            EchoContent::Full(p) => p.root_hash(),
        }
    }

    /// Returns Proof if type is Full else returns None.
    pub fn proof(&self) -> Option<&Proof<Vec<u8>>> {
        match &self {
            EchoContent::Hash(_) => None,
            EchoContent::Full(p) => Some(p),
        }
    }
}

//broadcast的代码会返还一个最新的broadcast结构体数据，同时，还会将一系列在这个broadcast中执行的操作导致的所有状态记录在step中。

/*#[derive(Debug)]
enum SigState<N> {
    /// The threshold signature fot this broadcast instance was generated or not.
    Complete(bool),
    /// The threshold signature is not known yet.
    InProgress(Box<ThresholdSign<N>>),
}

impl<N> SigState<N> {
    /// Returns the value, if this coin has already decided.
    fn value(&self) -> Option<bool> {
        match self {
            CoinState::Decided(value) => Some(*value),
            CoinState::InProgress(_) => None,
        }
    }
}

impl<N> From<bool> for SigState<N> {
    fn from(value: bool) -> Self {
        SigState::Decided(value)
    }
}*/


    //Handles a step returned from the `ThresholdSign`.
    /*fn on_ts_step(&mut self, ts_step: threshold_sign::Step<N>) -> Result<Step<N>> {
        let mut step = Step::default();
        let to_msg = |c_msg| MessageContent::Coin(Box::new(c_msg));
        let ts_output = step.extend_with(ts_step, FaultKind::CoinFault, to_msg);
        if let Some(sig) = ts_output.into_iter().next() {
            // Take the parity of the signature as the coin value.
            self.sigstate = Decided;//!!!!!这个地方看应该怎么写，也就是让sigstate的状态变成true
        }
        Ok(step)
    }*/

    /*fn on_ts_step(&mut self, ts_step: threshold_sign::Step<N>) -> Result<Step<N>, Error> {
        let mut step = Step::default();
        let to_msg = |c_msg| MessageContent::Coin(Box::new(c_msg));
        let ts_output = step.extend_with(ts_step, FaultKind::CoinFault, to_msg);
        
        // Check if the threshold signature is complete
        if let Some(sig) = ts_output.into_iter().next() {
            // Store the complete signature in the Broadcast structure
            self.thresholdsignature = sig;
            
            // Update the sigstate to Complete with true
            self.sigstate = SigState::Complete(true);
        }
        
        Ok(step)
    }*/





    /*fn validate_hash(&self, sender_id: &N, hash: &Digest) -> bool {
        // Step 1: Check if 'readys' already contains hash values
        let existing_hashes: Vec<&Vec<u8>> = self.readys.values()
            .filter(|(hash, _)| !hash.is_empty())
            .map(|(hash, _)| hash)
            .collect();
            
        if !existing_hashes.is_empty() {
            // Pick the first non-empty hash as the representative
            let representative_hash = &existing_hashes[0];
    
            // Check if the new hash matches the existing hashes
            if representative_hash != hash {
                return false;
            }
        } else {
            // Step 2: If 'readys' is empty, then check 'echos'
            if let Some(EchoContent::Full(p)) = self.echos.get(sender_id) {
                if p.root_hash() != new_hash {
                    return false;
                }
            } else {
                // If no matching hash found in 'echos', return false
                return false;
            }
        }
        true
    }*/
    

    //！！！！需要核实，这样用可能会存在问题。核实is_valid_share的输入参数，这个地方应该是有问题的
    /*fn validate_share(&self, sender_id: &N, signature_share: &SignatureShare, hash: &Digest) -> bool {
        let hash = root_hash;
        if ThresholdSign.is_valid_share(sender_id, signature_share) {
            return true;
        } else {
            return false;
        }
    }*/
    //！！！后续需要核实
    /*fn try_combine_signatures(&mut self) -> Result<Option<Signature>, Error> { // Assuming Error is defined in your code
        // 检查是否已经收到足够的签名shares。
        if self.readys.len() <= self.val_set.num_faulty() {
            return Ok(None);
        }

        // 从已收到的签名shares中提取shares。
        let shares: Vec<_> = self.readys.values().map(|&(_, ref share)| share.clone()).collect();

        // 使用`ThresholdSign`的方法来合成签名。
        match self.threshold_sign.combine_signatures(&shares) {
            Ok(signature) => {
                // 将生成的签名存储在 epoch_signatures 字典中
                self.epoch_signatures.insert(self.our_id.clone(), Some(signature.clone()));
                Ok(Some(signature))
            },
            Err(_) => Err(Error::FailedToCombineSignatures), // Make sure this is a valid error variant
        }
    }*/

        // 设置要签名的文档哈希
        //threshold_sign.set_document(hash).expect("Setting document should succeed");

        // 生成 signature share
        /*let secret_key_share = match self.val_set.secret_key_share() {
            Some(sks) => sks.sign_g2(hash),
            None => return Err(Error::DocumentHashIsNone),  // Replace with an appropriate error.
        };

        // Generate the SignatureShare.
        let signature_share = secret_key_share.sign_g2(hash);
        let step = threshold_sign.sign().expect("Signing should succeed");*/

        // 现在，step 包含一个 signature share，你可以从中提取出来，并根据需要进行广播或存储。

        /*let signature_share_message = step.messages.get(0).expect("There should be a signature share message");
        let signature_share = match &signature_share_message.payload {
            Message(share) => share,
            _ => panic!("Unexpected message type"),
        };*/
        //也许不需要设置send_message 这个方法


    
        /*let signature_share = if let Message::Sig(signature) = sig_msg {
            signature.clone()
        } else {
            return Err(Error::InvalidMessageType); // Assuming InvalidMessageType is a defined error
        };*/

        // Validate that the hash in the Ready message matches the hash in previous Echo and Value messages
        // (Assume validate_hash method exists that checks the hash against stored Echo and Value messages)
        // Validate the hash
        /*if !self.validate_hash(sender_id: &N, hash, &Digest) {
            warn!(
                "Node {:?} received Ready with hash {:?} from {:?} that doesn't match the hash stored in Echos",
                self.our_id(),
                hash,
                sender_id

            );
            return Ok(Fault::new(sender_id.clone(), FaultKind::Invalidreadyhash).into());;
        }*/

        // Validate the signature share
        // If the proof is invalid, log the faulty-node behavior, and ignore.
        /*if !self.validate_share(sender_id, hash, signature_share) {
            return Ok(Fault::new(sender_id.clone(), FaultKind::InvalidShare).into());
        }*/
