use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Arc;
use rand::Rng;
use log::warn;
use crate::crypto::{hash_g2, Signature, SignatureShare};
use crate::threshold_sign::ThresholdSign;
use crate::{ConsensusProtocol, NetworkInfo, NodeIdT, SessionIdT, Fault, Target};
use crate::broadcast::merkle::Digest;
use super::{Error, FaultKind, Message, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};


//这个文件会被更高级的文件调用。这个文件的propose是发送一个门限签名share，handle message也就是处理收到的门限签名share
/// try_output就是合成门限签名后并计算被选中的节点id。
/// 如果binary_agreement的输出结果是false，则还需要调用这个文件中的new方法，创建新的LeaderSelection<N, S>；
/// 同时，调用propose方法，重新选择leader
/// 因此，这个文件要么在cbc_set的输出产生时被调用，要么在binary_agreement的输出结果是false时被调用。
#[derive(Debug)]
pub struct LeaderSelection<N, S> {
    pub our_id: N,
    netinfo: Arc<NetworkInfo<N>>,
    /// Session identifier, to prevent replaying messages in other instances.
    session_id: S,
    leader_round_id: u64,
    max_future_leader_round_ids: u64,
    signatures: Vec<(N, (Digest, Signature))>,
    signature_shares: BTreeMap<N, SignatureShare>,
    incoming_queue: BTreeMap<u64, BTreeMap<N, SignatureShare>>,
    leader: Option<N>,
    decided: Option<bool>,
    complete: bool,
}

pub type Step<N> = crate::Step<Message, (u64, (N, Vec<(N, (Digest, Signature))>)), N, FaultKind>;

impl<N: NodeIdT, S: SessionIdT> ConsensusProtocol for LeaderSelection<N, S> {
    type NodeId = N;
    type Input = Vec<(N, (Digest, Signature))>;
    type Output = (u64, (N, Vec<(N, (Digest, Signature))>));
    type Message = Message;
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, _rng: &mut R) -> Result<Step<N>> {
        self.propose(input)
    }

    /// Receive input from a remote node.
    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        message: Message,
        _rng: &mut R,
    ) -> Result<Step<N>> {
        self.handle_message(sender_id, message)
    }

    /// Whether the algorithm has terminated.
    fn terminated(&self) -> bool {
        self.complete
    }

    fn our_id(&self) -> &Self::NodeId {
        self.netinfo.our_id()
    }

}

impl<N: NodeIdT, S: SessionIdT> LeaderSelection<N, S> {
    /// 创建一个新的`LeaderSelection`实例。
    pub fn new(our_id: N,  netinfo: Arc<NetworkInfo<N>>, session_id: S) -> Result<Self> {
        Ok(LeaderSelection {
            our_id,
            session_id,
            leader_round_id: 0,
            max_future_leader_round_ids: 6,
            netinfo,
            signatures: Vec::new(), 
            signature_shares: BTreeMap::new(), 
            incoming_queue: BTreeMap::new(), 
            leader: None,
            decided: None,
            complete: false,
        })
    }

    /*#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct LeaderSelectionMessageShare<N> {
        final_messages: Vec<FinalMessage>,
        signature_share: Option<SignatureShare>,
        proposer_id: N,
    }*/
    fn hash_to_digest(&mut self, value_map_str: &str) -> [u8; 32] {
        let mut hasher = DefaultHasher::new();
        value_map_str.hash(&mut hasher);
        let hash_code = hasher.finish();
        // 将 u64 转换为 [u8; 32]，填充其余字节为 0
        let mut digest = [0u8; 32];
        for i in 0..8 {
            digest[i] = ((hash_code >> (i * 8)) & 0xff) as u8;
        }
        digest
    }

     /// Initiates the leader selection. This must only be called by the proposer node.
     /// input应该是被cbc的output生成，一旦cbc的output生成就会初始化一个input == 0，并让input作为参数输入到该文件的propose方法中
     pub fn propose(&mut self, signatures: Vec<(N, (Digest, Signature))>) -> Result<Step<N>> {
        if !self.netinfo.is_node_validator(&self.our_id) {
            return Ok(Step::default());
        }

        self.signatures = signatures;
        //let content 将session_id和leader_round_id合成，并赋值给content

        // Hash the session_id
        //let session_id_bytes = self.session_id.to_be_bytes();
        let hash_session_id = self.hash_to_digest(&self.session_id.to_string());


        // Hash the leader_round_id; convert it to bytes first
        let leader_round_id = self.leader_round_id.clone();
        let hash_leader_round_id = self.hash_to_digest(&leader_round_id.to_string());

        let mut combined_hash = Vec::with_capacity(64);

        // 将两个数组的元素添加到 Vec<u8> 中
        combined_hash.extend_from_slice(&hash_session_id);
        combined_hash.extend_from_slice(&hash_leader_round_id);

        // Concatenate the two hashes
        // Hash the concatenated value to generate 'content'
        //let content = hash_g2(&combined_hash);

        let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));

        ts.doc_hash = Some(hash_g2(&combined_hash));  

        let _sig_step = ts.sign();
        let signature_share = ts.signature_share.expect("Signature share not generated");
        let sig_msg = Message {leader_round_id, signature_share};
        let step: Step<_> = Target::all().message(sig_msg.clone()).into();
        let other_step = self.handle_message(&self.our_id.clone(), sig_msg)?;
        Ok(step.join(other_step))
    }


    pub fn handle_message(&mut self, sender_id: &N, msg: Message) -> Result<Step<N>> {
        let Message { leader_round_id, signature_share } = msg;
        if self.decided.is_some() || (leader_round_id < self.leader_round_id) {
            // Message is obsolete: We are already in a later epoch or terminated.
            Ok(Step::default())
        } else if leader_round_id > self.leader_round_id + self.max_future_leader_round_ids {
            Ok(Fault::new(sender_id.clone(), FaultKind::InvalidEpoch).into())
        } else if leader_round_id > self.leader_round_id {
            // Message is for a later epoch. We can't handle that yet.
        
            // Access or create the BTreeMap corresponding to this leader_round_id
            let leader_round_id_state = self.incoming_queue
            .entry(leader_round_id)
            .or_insert_with(BTreeMap::new);
        
            // Insert the message for this sender_id in the BTreeMap
            leader_round_id_state.insert(sender_id.clone(), signature_share);
            
            Ok(Step::default())
        } else {
            self.handle_signature_share(sender_id, signature_share)
        }
    }//只处理这个轮次的消息


    pub fn handle_signature_share(&mut self, sender_id: &N,  signature_share: SignatureShare) -> Result<Step<N>> {
        let step = Step::default();
        if self.signature_shares.contains_key(sender_id) {
            warn!("Node {:?} received sig multiple times from {:?}.", self.our_id(), sender_id);
            return Ok(Step::default());
        }
        // Step 4: Check if self.value_map_hash is empty or not
        //let content 将session_id和leader_round_id合成，并赋值给content
        let hash_session_id = self.hash_to_digest(&self.session_id.to_string());


        // Hash the leader_round_id; convert it to bytes first
        let leader_round_id = self.leader_round_id;
        let hash_leader_round_id = self.hash_to_digest(&leader_round_id.to_string());

        let mut combined_hash = Vec::with_capacity(64);

        // 将两个数组的元素添加到 Vec<u8> 中
        combined_hash.extend_from_slice(&hash_session_id);
        combined_hash.extend_from_slice(&hash_leader_round_id);

        // Concatenate the two hashes
        // Hash the concatenated value to generate 'content'
        //let content = hash_g2(&combined_hash);

        let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));

        ts.doc_hash = Some(hash_g2(&combined_hash));  

        if !ts.is_share_valid(sender_id, &signature_share) {
            let fault_kind = FaultKind::InvalidSignatureShare;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        //threshold_sign.set_document(value_map_hash.clone()).expect("Setting document should succeed");
    
        // 您需要确保 `echo_msg.content` 和 `is_share_valid` 方法的期望类型匹配
        // Step 6: Add the SignatureShare to self.echoes
        self.signature_shares.insert(sender_id.clone(), signature_share);   
        Ok(step.join(self.try_output()?))
    }
        

    /// 计算Leader。
    pub fn try_output(&mut self) -> Result<Step<N>> {
        let mut step =Step::default();
        if self.leader.is_some() {
            return Ok(step);//
        }
            
        if self.signature_shares.len() >= 2 * self.netinfo.num_faulty() + 1 {//这里需要注意 self.signature_shares.len()这个写法有没有问题
            // Generate the threshold signature
            let hash_session_id = self.hash_to_digest(&self.session_id.to_string());


            // Hash the leader_round_id; convert it to bytes first
            let leader_round_id = self.leader_round_id;
            let hash_leader_round_id = self.hash_to_digest(&leader_round_id.to_string());

            let mut combined_hash = Vec::with_capacity(64);

            // 将两个数组的元素添加到 Vec<u8> 中
            combined_hash.extend_from_slice(&hash_session_id);
            combined_hash.extend_from_slice(&hash_leader_round_id);

            let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));

            
            ts.doc_hash = Some(hash_g2(&combined_hash));  

            let unwrapped_doc_hash = ts.doc_hash.unwrap();
            let signature = ts.combine_and_verify_sig(unwrapped_doc_hash).expect("Signature share not generated");

            let bytes = signature.to_bytes();
            let sig_as_usize = usize::from_le_bytes(bytes[0..std::mem::size_of::<usize>()].try_into().unwrap());
            let node_count = self.netinfo.num_nodes();
                // 计算leader。
            let leader_idx = sig_as_usize % node_count;

            let leader_id = self.netinfo.validator_set()
                .all_indices()
                .find(|&(_, idx)| idx == &leader_idx)
                .map(|(id, _)| id.clone());

            // 现在，leader_id是Option<N>类型。你可能想要处理None情况（例如，通过返回错误）。
            if let Some(leader_id) = leader_id {
                self.leader = Some(leader_id);
                let leader = self.leader.clone().unwrap();
                step = step.with_output((self.leader_round_id.clone(), (leader.clone(), self.signatures.clone())));
                self.complete = true;
            } else {
                warn!("impossible situation.");// 处理没有找到匹配的节点ID的情况
            } 
        }
        Ok(step)
    }

    pub fn handle_decide(&mut self, b: bool) -> Result<Step<N>> {
    //更上一层的模块通过获得ba的输出后将该输出作为输入调用handle_decide方法
        /*if self.our_id != sender_id {
            return Ok(Step::default());
        }*/

        if b {
            self.decided = Some(true);
            Ok(Step::default())//这个地方需要进一步讨论
        } else {
            self.signature_shares.clear();
            self.leader = None;
            self.leader_round_id += 1;
            self.decided = None;
            let cbc_output = self.signatures.clone();
            let mut step = self.propose(cbc_output)?;
            if let Some(signature_shares_map) = self.incoming_queue.remove(&self.leader_round_id) {
                for (sender_id, signature_share) in signature_shares_map {
                    step = step.join(self.handle_signature_share(&sender_id, signature_share)?);
                }
            }
            Ok(step)
        }
    }
}
    // 获取当前选定的Leader。
    /*pub fn get_leader(&self) -> Option<&N> {
        self.leader.as_ref()
    }*/



/*pub fn update_and_broadcast_leader_selection_message(&mut self, cbc_final: Vec<FinalMessage>) -> Result<(), &'static str> {
        // 更新Final消息。
        self.leader_selection_message.final_messages = cbc_final;
        
        // 检查是否收到了N-f个Final消息。
        if self.leader_selection_message.final_messages.len() >= self.threshold_sign.netinfo().all_ids().len() - self.threshold_sign.netinfo().num_faulty() {
            // 生成门限签名份额。
            let epoch_id_hash = self.threshold_sign.doc_hash.ok_or("Epoch ID hash not set")?;
            let sks = self.threshold_sign.netinfo().secret_key_share().ok_or("Failed to retrieve secret key share")?;
            let signature_share = sks.sign_g2(epoch_id_hash);

            // 验证签名份额。
            let pk_share = self.threshold_sign.netinfo().public_key_share(&self.leader_selection_message.sender).ok_or("Unknown sender")?;
            if !pk_share.verify_g2(&signature_share, epoch_id_hash) {
                return Err("Invalid signature share");
            }
            
            // 更新LeaderSelectionMessage的签名份额。
            self.leader_selection_message_share.final_messages = cbc_final;
    
            // 检查是否收到了N-f个Final消息。
            if self.leader_selection_message_share.final_messages.len() >= self.threshold_sign.netinfo().all_ids().len() - self.threshold_sign.netinfo().num_faulty() {
                // 生成门限签名份额。
                let epoch_id_hash = self.threshold_sign.doc_hash.ok_or("Epoch ID hash not set")?;
                let sks = self.threshold_sign.netinfo().secret_key_share().ok_or("Failed to retrieve secret key share")?;
                let signature_share = sks.sign_g2(epoch_id_hash);
        
                // 验证签名份额。
                let pk_share = self.threshold_sign.netinfo().public_key_share(&self.our_id).ok_or("Unknown sender")?;
                if !pk_share.verify_g2(&signature_share, epoch_id_hash) {
                    return Err("Invalid signature share");
                }
                
                // 更新LeaderSelectionMessageShare的签名份额。
                self.leader_selection_message_share.signature_share = Some(signature_share);
        
                // 广播LeaderSelectionMessageShare。
                let mut step = Step::default();
                for id in self.threshold_sign.netinfo().all_ids() {
                    if *id == self.our_id {
                        // 这个消息是给当前节点的，所以我们不发送，但可能进行其他处理。
                        continue;
                    }
                    let msg = Target::node(id.clone()).message(self.leader_selection_message_share.clone());
                    step.messages.push(msg);
                }
        
                Ok(())
            }
        }
    }*/

    /*pub fn handle_leader_selection_message_share(&mut self, message: LeaderSelectionMessage<N>) -> Result<(), &'static str> {
        // 验证final消息.
        if self.received_leader_selection_message.contains(&message.sender) {
            return Err("Duplicate message from node");
        }
        for final_msg in &message.final_messages {
            let public_key = self.threshold_sign.netinfo().public_key_set().public_key();
            if !public_key.verify_g2(&final_msg.signature, final_msg.doc_hash.as_slice()) {
                return Err("Invalid final message signature");
            }
        }
        let epoch_id_hash = self.threshold_sign.doc_hash.ok_or("Epoch ID hash not set")?;
        let sender_pk_share = self.threshold_sign.netinfo().public_key_share(&message.sender).ok_or("Unknown sender")?;
        if !sender_pk_share.verify_g2(&message.signature_share, epoch_id_hash) {
            return Err("Invalid signature share");
        }

        // 存储final消息和门限签名share。
        self.cbc_final_messages.insert(message.sender.clone(), (message.final_messages, message.signature_share));
        self.received_leader_selection_message.insert(message.sender);

        self.generate_threshold_signature()

        Ok(())
    }

    fn generate_threshold_signature(&mut self) -> Result<(), &'static str> {
        if self.cbc_final_messages.len() < self.threshold_sign.netinfo().all_ids().len() - self.threshold_sign.netinfo().num_faulty() {
            return Ok(());
        }

        let shares: Vec<_> = self.cbc_final_messages.values().map(|(_, share)| share.clone()).collect();
        match self.threshold_sign.combine_and_verify_sig(&self, hash: G2) {
            Ok(signature) => {
                // 计算leader。
                self.leader = Some(self.calculate_leader(signature));
            },
            Err(_) => return Err("Failed to combine or verify the threshold signature")
        }

        Ok(())
    }*/
//let leader_round_id = self.leader_round_id;
            //需要从self.incoming_queue中提取出键leader_round_id所对应的键值对；
            //然后，将键leader_round_id所对应的值BTreeMap<N, SignatureShare>进行处理；
            //具体的处理方式为：1）遍历键leader_round_id所对应的值BTreeMap<N, SignatureShare>中的每个键值对
            //2）将每个键值对中的内容sender_id和SignatureShare进行分别处理
            //键leader_round_id和SignatureShare打包成message；然后，将sender_id和message作为输入参数传递给self.handle_signature_share——也就是执行step.extend(self.handle_signature_share(&sender_id, message)?)
            //3)一旦处理了键leader_round_id所对应的值BTreeMap<N, SignatureShare>中的一个键值对，就将这个键值对从BTreeMap<N, SignatureShare>删除
            //直到将leader_round_id所对应的值BTreeMap<N, SignatureShare>中的所有键值对全部删除。



