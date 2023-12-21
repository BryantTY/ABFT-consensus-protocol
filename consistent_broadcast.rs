use std::sync::Arc;
use std::collections:: BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use log::warn;
use rand::Rng;
//use coincurve::{PublicKey, PrivateKey};
//use serde::{Serialize, Deserialize};
use crate::crypto::{hash_g2, Signature, SignatureShare};
use crate::{NetworkInfo, NodeIdT, SessionIdT, Target, ConsensusProtocol};
use crate::fault_log::Fault;
use crate::threshold_sign::ThresholdSign;
use crate::broadcast::merkle::Digest;
use super::{Error, FaultKind, Message, MessageContent, Result};




/*enum ConsistentBroadcastMessage {
    ConsistentBroadcast_SEND(Vec<u8>),
    ConsistentBroadcast_ECHO(SignatureShare),
    ConsistentBroadcast_FINAL(Vec<u8>, Vec<SignatureShare>),
}*/
#[derive(Debug, Clone)] 
pub struct ConsistentBroadcast<N, S> {
    /// Shared network information.
    netinfo: Arc<NetworkInfo<N>>,
    /// Session identifier, to prevent replaying messages in other instances.
    session_id: S,
    /// Maximum number of future epochs for which incoming messages are accepted.
    //max_future_epochs: u64,//需要核实到底需不需要
    //self's id
    our_id: N,
    proposer_id: N,
    //information of the newtork
    //val_set: Arc<ValidatorSet<N>>,
    //if our_id==proposer_id, sent_value can become true at a certain time point; otherwise, it can only be false
    sent_value: bool,
    c_value: Vec<(N, (Digest, Signature))>, //怎么去验证这个Signature，最好不要调用RBC中的信息。需要时2f+1 out of N 的门限签名方案
    value_map_hash: Option<Digest>,
    c_echoes: BTreeMap<N, SignatureShare>, // 存储从不同节点收到的ECHO消息中的签名片段
    c_final: Option<(N, (Digest, Signature))>, // 存储每个节点的门限签名和相关的消息哈希
    final_sent: bool,
    final_received: bool,
    decided: bool,
}

/// A `Broadcast` step, containing at most one output.
pub type Step<N> = crate::Step<Message<N>, (N, (Digest, Signature)), N, FaultKind>;


impl<N: NodeIdT, S: SessionIdT> ConsensusProtocol for ConsistentBroadcast<N, S> {
    type NodeId = N;
    type Input  = Vec<(N, (Digest, Signature))>;  // 提供的RBC实例的输入信息
    type Output = (N, (Digest, Signature)); // bc_signature
    type Message = Message<N>; //需要对消息类型进行修改
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, _rng: &mut R) -> Result<Step<N>> {
        self.propose(input)
    }

    fn handle_message<R: Rng>(
        &mut self,
        sender_id: &Self::NodeId,
        message: Message<N>,
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


impl<N: NodeIdT, S: SessionIdT> ConsistentBroadcast<N, S> {
    /// Creates a new CBC instance to be used by node `our_id`.
    pub fn new(netinfo: Arc<NetworkInfo<N>>, 
        session_id: S, 
        our_id: N, 
        proposer_id: N) -> Result<Self> {

    Ok(ConsistentBroadcast {
        netinfo: netinfo.clone(),
        session_id,
        our_id,
        proposer_id,
        sent_value: false,
        value_map_hash: None,
        c_value: Vec::new(),
        c_echoes: BTreeMap::new(),
        c_final: None,
        final_sent: false,
        final_received: false,
        decided: false,
        })
    }

    pub fn propose(&mut self, input: Vec<(N, (Digest, Signature))>) -> Result<Step<N>> {//BTreeMap<N, (Digest, Signature)>是否表达正确需要核实
        if self.our_id != self.proposer_id {
            return Err(Error::InstanceCannotPropose);
        }

        if self.sent_value == true {
            return Err(Error::ValueAlreadySent);
        }

        self.sent_value = true;  
        self.send_value(input)  
    }


    /// Handles a message received from `sender_id`.
    pub fn handle_message(&mut self, sender_id: &N, msg: Message<N>) -> Result<Step<N>> {
        if !self.netinfo.is_node_validator(sender_id) {
            return Err(Error::UnknownSender);
        }
    
        let Message {proposer_id, content} = msg.clone();
        match content {
            MessageContent::Cbcvalue(value) => self.handle_value(sender_id, msg),
            MessageContent::Cbcecho(echo_msg) => self.handle_echo(sender_id, msg),
            MessageContent::Cbcfinal(final_msg) => self.handle_final(sender_id, msg),
        }
    }
    

   


    pub fn proposer_id(&self) -> &N {
        &self.proposer_id
    }

    /// Returns the set of all validator IDs.
    /*pub fn net_info(&self) -> &Arc<ValidatorSet<N>> {
        // 假设您已在CBC结构体中有一个字段名为 `val_set` 来存储验证者集合。
        &self.netinfo
    }*/

    fn send_value(&mut self, value: Vec<(N, (Digest, Signature))>) -> Result<Step<N>> {
        // MessageContent包含3种类型，value, echo, final
    
        let proposer_id = self.our_id.clone();
        let value_msg = Message { 
            proposer_id, 
            content: MessageContent::Cbcvalue(value),
           
        };
        let step: Step<N> = Target::all().message(value_msg.clone()).into();
        let handle_result = self.handle_value(&self.our_id.clone(), value_msg)?;
        Ok(step.join(handle_result))

        //Ok(step.join(self.handle_value(proposer_id, value_msg))) // 注意这里使用了 self 来调用 handle_value
    }
    

    fn handle_value(&mut self, sender_id: &N, value_msg: Message<N>) -> Result<Step<N>> {
        if value_msg.proposer_id.clone() != self.proposer_id.clone() {
            return Err(Error::InvalidProposer);
        }

        //需要判断value的Message类型，如果是cbc_value类型则执行下一步，否则，需要报错——消息类型不匹配
        let step = Step::default();
        // 检查我们是否已经接收过一个SEND消息，并确保它与当前消息匹配。
        if !self.c_value.is_empty() {
            warn!(
                "Node {:?} received SEND({:?}) multiple times from {:?}.",
                self.our_id,
                value_msg,
                sender_id
            );
            return Err(Error::MultipleValuesFromSender);
        }
        let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));
        
        match &value_msg.content {
            MessageContent::Cbcvalue(map) => {
                let mut valid_sign_count = 0;
                //需要遍历所有的value中的值的所有内容，也就是N-f个digest和对应的threshold signature。然后分别验证这些threshold signature是否合法。
                //如果合法，则将(send_id, value)保存到self.c_value中。否则，就报错——无效的的value。
                //value_msg: BTreeMap<N, (Digest, Signature)>
                for (_key, (digest, signature)) in map.iter() {
                    // 设置文档哈希
                    ts.doc_hash = Some(hash_g2(digest.as_ref()));
                    let unwrapped_doc_hash = ts.doc_hash.unwrap();
                    //ts.doc_hash = Some(unwrapped_doc_hash.clone());
                    // 使用 threshold_sign 来验证这些签名
                    if ts
                    .netinfo()
                    .public_key_set()
                    .public_key()
                    .verify_g2(&signature, unwrapped_doc_hash) {
                        valid_sign_count += 1;
                    } else {
                        let fault_kind = FaultKind::InvalidValue;
                        return Ok(Fault::new(sender_id.clone(), fault_kind).into());
                    }
                }

                // 检查是否有足够数量的有效签名
                if valid_sign_count.clone() != self.netinfo.num_nodes() - self.netinfo.num_faulty() {
                    let fault_kind = FaultKind::InvalidValue;
                    return Ok(Fault::new(sender_id.clone(), fault_kind).into());
                }

                self.c_value = map.clone();
                let value_map_str = format!("{:?}", value_msg.clone());
                let value_map_str_hash = self.hash_to_digest(&value_map_str);
        
                self.value_map_hash = Some(value_map_str_hash); //确定hash_g2(value_map_str.as_bytes())的输出数据类型
                let digest = self.value_map_hash.unwrap();
        
                //如果已经将(send_id, value)保存到self.c_value了，就继续调用send_echo方法。
                Ok(step.join(self.send_echo(digest)?))
            }
            _ => {
                let fault_kind = FaultKind::InvalidValue;
                return Ok(Fault::new(sender_id.clone(), fault_kind).into());
            }
        }               
    }

    fn hash_to_digest(&self, value_map_str: &str) -> [u8; 32] {
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
        
       

    fn send_echo(&mut self, digest: Digest) -> Result<Step<N>> {
        if !self.netinfo.is_node_validator(&self.our_id) {
            return Ok(Step::default());
        }


        // 创建 ThresholdSign 对象
        let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));

        ts.doc_hash = Some(hash_g2(digest.as_ref()));  
        let ts_sign_result = ts.sign();
        let signature_share = ts.signature_share.expect("Signature share not generated");
        let mut step: Step<N> = Step::default();
        let content = MessageContent::Cbcecho(signature_share.clone());

        let echo_msg = Message {
            proposer_id: self.our_id.clone(),
            content: content.clone(),  // clone content here
        };

        let step: Step<_> = Target::node(self.our_id.clone()).message(echo_msg.clone()).into();  // clone echo_msg here

        if self.our_id == self.proposer_id {
            // reconstruct echo_msg
            let our_id_clone = self.our_id.clone(); 
            let echo_msg = Message {
                proposer_id: self.our_id.clone(),
                content,  // use cloned content here
            };
            let other_step = self.handle_echo(&our_id_clone, echo_msg)?;
            //let other_step = self.handle_echo(&self.our_id, echo_msg)?;//这一句包含了可变借用(self.handle_echo)和不可变借用(&self.our_id)，会导致数据竞争
            Ok(step.join(other_step))
        } else {
            Ok(step)
        }

    }

    fn handle_echo(&mut self, sender_id: &N, echo_msg: Message<N>) -> Result<Step<N>> {
         //需要判断value的Message类型，如果是cbc_value类型则执行下一步，否则，需要报错——消息类型不匹配
        if !self.netinfo.is_node_validator(sender_id) {
            return Ok(Step::default());
        }

        if self.our_id != echo_msg.proposer_id && self.our_id != self.proposer_id {
            let fault_kind = FaultKind::ReceivedInvalidEchoMessage;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }

        // Step 3: Check if this is the first ECHO message from this sender
        if self.c_echoes.contains_key(sender_id) {
            warn!("Node {:?} received ECHO multiple times from {:?}.", self.our_id, sender_id);
            return Ok(Step::default());
        }
        // Step 4: Check if self.value_map_hash is empty or not
        if let Some(value_map_hash) = &self.value_map_hash {
            //Step 5: Check if the signatureshare is valid or not
            let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));
            let unwrapped_doc_hash = self.value_map_hash.unwrap();//不会改变self.value_map_hash的值
            ts.doc_hash = Some(hash_g2(unwrapped_doc_hash.as_ref()));
            let Message {proposer_id, content} = echo_msg;
            if let MessageContent::Cbcecho(signature_share) = &content {
                if !ts.is_share_valid(sender_id, signature_share) {
                    let fault_kind = FaultKind::InvalidSignatureShare;
                    return Ok(Fault::new(sender_id.clone(), fault_kind).into());
                }
                self.c_echoes.insert(sender_id.clone(), signature_share.clone());
            } else {
                let fault_kind = FaultKind::InvalidMessageType;
                return Ok(Fault::new(sender_id.clone(), fault_kind).into());
            }
        }
        else {
            let fault_kind = FaultKind::ReceivedInvalidEchoMessage;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        // Step 7: Check if we have at least 2f+1 SignatureShares
        if self.c_echoes.len() == 2 * self.netinfo.num_faulty() + 1 {
            // Generate the threshold signature
            let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));
            let unwrapped_doc_hash = self.value_map_hash.unwrap();
            ts.doc_hash = Some(hash_g2(unwrapped_doc_hash.as_ref()));
            let unwrapped_doc_hash = ts.doc_hash.unwrap();
            let threshold_signature = ts.combine_and_verify_sig(unwrapped_doc_hash).expect("Signature share not generated");

            //self.c_final.insert(our_id.clone(), (content, threshold_signature))
            // Step 8: Call send_final method
            self.send_final(threshold_signature)?; // Assuming send_final is a defined method
        }
        Ok(Step::default())
    }


    fn send_final(&mut self, threshold_signature: Signature) -> Result<Step<N>> {
        // Step 1: Check if FINAL has already been sent, based on a hypothetical self.FINAL_sent field.
        if self.final_sent == true {
            return Err(Error::FinalAlreadySent); // Assuming Error::FinalAlreadySent is a defined error
        }
    
        // Step 2: Mark that FINAL has been sent.
        self.final_sent = true;     
        // Step 3: Create the message to be sent.
        let unwrapped_value_map_hash = self.value_map_hash.unwrap();
        let final_msg = Message {
            proposer_id: self.our_id.clone(), // 假设 `self.our_id` 类型实现了 `Clone` trait
            content: MessageContent::Cbcfinal((unwrapped_value_map_hash.clone(), threshold_signature.clone())), // 假设 `Signature::new()` 是一个有效的方法
        };
        let step: Step<_> = Target::all().message(final_msg.clone()).into();
        Ok(step)
    }
        

    fn handle_final(&mut self, sender_id: &N, final_msg: Message<N>) -> Result<Step<N>> {
        // step 1 验证发送者是否是proposer。
        if sender_id.clone() != self.proposer_id {
            let fault_kind = FaultKind::NonProposer;
            return Ok(Fault::new(sender_id.clone(), fault_kind).into());
        }
        //step 2 验证是否已经收到过该节点的CBC实例的final消息
        if self.final_received == true {
            return Err(Error::FinalAlreadyReceived);
        }     
        // Step 3: Validate the threshold_signature
        let step = Step::default();
        let mut ts = ThresholdSign::new(Arc::clone(&self.netinfo));
        match &final_msg.content {
            MessageContent::Cbcfinal((value_map_hash, threshold_signature)) => {
                ts.doc_hash = Some(hash_g2(value_map_hash.as_ref())); 
                let unwrapped_doc_hash = ts.doc_hash.unwrap();
                if !ts
                .netinfo()
                .public_key_set()
                .public_key()
                .verify_g2(threshold_signature, unwrapped_doc_hash) {
                    let fault_kind = FaultKind::InvalidFinal;
                    return Ok(Fault::new(sender_id.clone(), fault_kind).into()); // Assuming Error::VerificationFailed is a defined error
                } else {
                    self.value_map_hash = Some(value_map_hash.clone());
                    self.final_received = true;
                    let digest_hash = self.value_map_hash.unwrap();
                    self.c_final = Some((sender_id.clone(), (digest_hash, threshold_signature.clone())));
                    Ok(step.join(self.output()?))
                }
            },
            // 可以添加其他 MessageContent 类型的处理逻辑，如果需要的话。
            _ => {
                let fault_kind = FaultKind::InvalidFinal;
                return Ok(Fault::new(sender_id.clone(), fault_kind).into());
            } // Assuming Error::InvalidMessageContent is a defined error
        }
    }

    fn output(&mut self) -> Result<Step<N>> {
        // 创建一个新的Step实例
        let mut step = Step::default();

        if self.decided == true {
            return Err(Error::AlreadyDecided);
        } 

        self.decided = true; 
        // 将self.c_final的内容设置为step的输出
        //step = step.output.insert(self.c_final.clone());
        step = step.with_output(self.c_final.clone());
        // 返回包含self.c_final内容的step
        Ok(step)
    }  
}        



    /*fn is_for_current_instance(&self, signature_share: &SignatureShare) -> bool {
        // This is a placeholder. You need to implement the actual logic here.
        true
    }

    fn validate_signature_share(&self, signature_share: &SignatureShare) -> bool {
        // This is a placeholder. You need to implement the actual logic here.
        true
    }*/


   /* pub fn send(&mut self, input: Vec<u8>) -> Result<Step<N>> {
        // Check if the current instance is the leader/proposer
        if self.sid != self.leader {
            return Err(Error::InstanceCannotPropose);
        }

        // Check if the value has already been sent
        if self.final_sent {
            return Err(Error::MultipleInputs);
        }

        // Mark that the value has been sent
        self.final_sent = true;

        // In CBC, you might not need to split the input or use erasure codes,
        // but if you do, implement that logic here.

        // If you have a mechanism similar to Merkle trees for CBC, implement that here.
        // Otherwise, directly send the input as a SEND message.
        
        let mut step = Step::default();
        
        // Here, create your SEND message and broadcast it
        // For instance: 
        let msg = CbcMessage::Send(input);
        step.messages.push(Target::all().message(msg));

        // You might need to handle the sent value in CBC, similar to how `handle_value` works in Broadcast.
        // If so, implement that logic here.

        Ok(step)
    }*/


    // Handle the message process
    /*fn handle_message(&mut self, input: impl Fn() -> Vec<u8>) -> (Vec<u8>, Vec<SignatureShare>) {
        if self.pid == self.leader {
            let input_m = input();
            self.m = Some(input_m);
            self.digest_from_leader = Some(hash_g2(&self.m));
            let signature = self.threshold_sign.sign().expect("Sign failed");
            self.cbc_echo_sshares.insert(self.pid, signature);
            (self.send)(-1, CbcMessage::CBC_SEND(self.m.clone().unwrap()));
        }

        loop {
            let (j, msg) = (self.received)();

            match msg {
                CbcMessage::CBC_SEND(received_m) => {
                    self.handle_send(j, received_m);
                }
                CbcMessage::CBC_ECHO(sig_share) => {
                    self.handle_echo(j, sig_share);
                }
                CbcMessage::CBC_FINAL(received_m, sig_shares) => {
                    return self.handle_final(j, received_m, sig_shares);
                }
            }
        }
    }*/
  /*fn handle_echo(&mut self, sender_id: &N, value_map_hash: Digest, content: SignatureShare) -> Result<Step<N>> {
        //步骤1: 首先要检查发送者是不是validator
        //步骤2: 然后检查our_id==proposer_id==c_value中的N。如果是，则执行下一步，如果不是，则报错：自己不是这个CBC实例的proposer。
        //步骤3: 然后检查输入参数中的value_map_hash是否等于self.value_map_hash。如果是，则执行下一步，如果不是，则报错：无效的摘要。
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }

        // 步骤4: 检查这是否是从该发送者收到的第一条ECHO消息。
        if self.echoes.contains_key(sender_id) {
            warn!(
                "Node {:?} received ECHO multiple times from {:?}.",
                self.our_id(),
                sender_id,
            );
            return Ok(Step::default());
        }

        // 步骤5: 用threshold_sign.rs中的方法验证输入参数SignatureShare是否合法，其中输入参数value_map_hash: Digest,是签名的对象。
        //如果步骤5验证通过，则执行步骤6，否则报错。
        

        // 步骤6: 将signatureshare添加到self.echos中。
        self.echoes.insert(sender_id.clone(), signature_share);

        // 步骤7: 判断self.echoes中是否收到了2f+1个signature_share，如果是，则生成门限签名，如果不是，则返回默认步骤。
        if self.echoes.len() >= 2 * self.fault_estimate + 1 {
            ///生成门限签名
        } else {};
        //步骤8： 一旦生成门限签名，则调用send_final方法。其中生成的门限签名和自己的id是send_final方法的输入。

        Ok(Step::default())
    }*/

    /*验证发送者是否是这个CBC实例的leader。
        if !self.our_id == &self.proposer_id {
            return Err(FaultKind::UnexpectedFinalSender.into());
        }*/

        // step1: 验证是否是第一次发送FINAL消息：检查的逻辑是查看self.c_final中的值是否为空；如果为空，则返回默认步骤，如果不为空，则执行下一步。
        /*if self.FINAL_sent {
            warn!(
                "Node {:?} attempted to send FINAL multiple times.",
                self.our_id(),
            );
            return Ok(Step::default());
        }

        // step2: 更新self.FINAL_sent为true。
        self.FINAL_sent = true;  // 如果之前收到过该sender的FINAL消息，忽略它。
        if let Some((old_hash, _)) = self.finals.get(sender_id) {
            if old_hash == m_hash {
                warn!(
                    "Node {:?} received FINAL({:?}) multiple times from {:?}.",
                    self.our_id(),
                    m_hash,
                    sender_id
                );
                return Ok(Step::default());
            } else {
                return Ok(Fault::new(sender_id.clone(), FaultKind::MultipleFinals).into());
            }
        }

        // 存储接收到的FINAL消息及其门限签名。
        self.finals.insert(sender_id.clone(), (m_hash.clone(), threshold_signature.clone()));

        // 根据您的描述，这里不再需要额外的逻辑，例如广播新消息或做其他操作。
        // 如果需要的话，您可以在这里添加额外的逻辑。

        Ok(Step::default())
    }*/
            // If you wish to extract the SignatureShare for additional processing, you can do so here.
        /*if let Some(message) = sig_step.messages.first() {
            if let signature_share = &message.message {
                let sig_msg = Message::Sig(signature_share.clone());
                let prop_id = self.proposer_id;
                //let content = sig_msg;
                let echo_msg = Message {prop_id, sig_msg};
                let step: Step<_> = Target::Nodes(prop_id).message(echo_msg.clone()).into();//这一步需要修改，只发送给proposer,需要在Target下修改
                
                /*let additional_step: Step<_> = Target::all().message(sig_msg).into();
                //这一步需要修改，只发送给proposer,需要在Target下修改
                step = step.join(self.handle_threshold_signature(self.our_id, signature_share)?);
                step = step.join(additional_step);
                Ok(step)
                // Now, `signature_share` contains the SignatureShare.
                // You can add code here to process the SignatureShare further if needed.*/
            } else {
                Err(Error::Nosecretkey)
            }*/ 

 /*// 假设 c_value 是一个 BTreeMap<N, MessageContent>，其中 MessageContent 包含你想要签名的数据
        let value_map = self.c_value.get(&sender_id).expect("Value should exist for this sender");

        // 计算 value_map 的哈希。这里简单地用 Debug trait 输出，你应该使用合适的哈希函数。
        let value_map_str = format!("{:?}", value_map);
        let value_map_hash = hash_g2(value_map_str.as_bytes());  // 使用合适的哈希函数

        // 设置要签名的文档哈希
        ts.set_document(content).expect("Setting document should succeed");

        // 生成 signature share
        let step = threshold_sign.sign().expect("Signing should succeed");

        // 现在，step 包含一个 signature share，你可以从中提取出来，并根据需要进行广播或存储。
        let signature_share_message = step.messages.get(0).expect("There should be a signature share message");
        let signature_share = match &signature_share_message.payload {
            Message(share) => share,
            _ => panic!("Unexpected message type"),
        };
        //也许不需要设置send_message 这个方法
        let echo_msg = Message<N> { proposer_id: self.proposer_id, content: signature_share};
        let step: Step<_> = Target::all().message(echo_msg.clone()).into();//这一步需要修改，只发送给proposer,需要在Target下修改
        Ok(step)*/