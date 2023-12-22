use std::collections::BTreeMap;
//use hex_fmt::HexFmt;
//use log::debug;
use std::sync::Arc;
use crate::subset::BaSessionId;
use rand::Rng; // 如果您使用的是`rand` crate
use crate::{ConsensusProtocol, NodeIdT, SessionIdT, /*ValidatorSet,*/ NetworkInfo};
//use crate::threshold_sign::ThresholdSign;
use crate::crypto::Signature;

use super::merkle::Digest;
//use super::message::HexProof;
use super::{Error, FaultKind, Message, Result};
use super::{Broadcast, Step as BroadcastStep};

// 假设traits.rs在同一个crate中
// 或其他导入根据您的具体情况
pub type Step<N> = crate::Step<Message, Vec<(N, (Digest, Signature))>, N, FaultKind>;
/// An output with an accepted contribution or the end of the set.
#[derive(derivative::Derivative, Clone, PartialEq)]
#[derivative(Debug)]

pub struct BroadcastSet<N, S> {
    our_id: N,
    session_id: S,
    //val_set: Arc<ValidatorSet<N>>,
    netinfo: Arc<NetworkInfo<N>>,
    bc_signatures: Vec<(N, (Digest, Signature))>, // 使用 Option 类型
    broadcast_instance_outputs: BTreeMap<N, (Digest, Signature, Vec<u8>)>, // 包含 N 个元素
    broadcast_instances: BTreeMap<N, Broadcast<N>>,

   //contributions: BTreeMap<N, #[derivative(Debug(format_with = "util::fmt_hex"))] Vec<u8>>,
    complete: bool,
}


impl<N: NodeIdT, S: SessionIdT> ConsensusProtocol for BroadcastSet<N, S> {
    type NodeId = N;
    type Input  = Vec<u8>;  // 提供的RBC实例的输入信息
    type Output = Vec<(N, (Digest, Signature))>; // bc_signature
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
        self.complete
    }

    fn our_id(&self) -> &Self::NodeId {
        //&self.our_id
        &self.our_id
    }
}

impl <N: NodeIdT, S: SessionIdT>BroadcastSet<N, S> {
    pub fn new(our_id: N, netinfo: Arc<NetworkInfo<N>>, session_id: S) -> Result<Self> 
    {
        let bc_signatures: Vec<(N, (Digest, Signature))> = Vec::new();
        let mut broadcast_instances:BTreeMap<N, Broadcast<N>> = BTreeMap::new();
        let validators = netinfo.validator_set().clone();
        for (proposer_idx, proposer_id) in netinfo.all_ids().enumerate() {
            let _ba_id = BaSessionId {
                subset_id: session_id.clone(),
                proposer_idx: proposer_idx as u32,
            };
            //our_id: N, val_set: V, netinfo: Arc<NetworkInfo<N>>, proposer_id: N
            broadcast_instances.insert(
                proposer_id.clone(),
                Broadcast::new(our_id.clone(),  validators.clone(), netinfo.clone(), proposer_id.clone())?,
            );
        }
        let broadcast_instance_outputs:BTreeMap<N, ([u8; 32], Signature, Vec<u8>)>  = BTreeMap::new();

        Ok(BroadcastSet {
            our_id,
            session_id,
            netinfo,
            bc_signatures,
            broadcast_instances,
            broadcast_instance_outputs,
            complete: false,
        })
    }

    pub fn broadcast(&mut self, value: Vec<u8>) -> Result<Step<N>> {
        let bc_step: crate::Step<Message, (N, ([u8; 32], Signature, Vec<u8>)), N, FaultKind> = self
            .broadcast_instances
            .get_mut(&self.our_id)//从 proposal_states 映射中获取当前节点（our_id）的 ProposalState 的可变引用。
            .ok_or(Error::UnknownProposer)?
            .broadcast(value)?;//相当于启动自己的PRBC实例。并将该实例的step最新状态赋值给prop_step
        let our_id = self.our_id.clone();
        //提取prop_step中可能有的output到现有的bcset的step状态中
        let mut step: crate::Step<Message, Vec<(N, ([u8; 32], Signature))>, N, FaultKind> = self.convert_step(&our_id, bc_step)?;
        let from_p_msg = |p_msg: Message| p_msg;
        let _bc_step_1 = self
        .broadcast_instances
        .get_mut(&self.our_id)//从 proposal_states 映射中获取当前节点（our_id）的 ProposalState 的可变引用。
        .ok_or(Error::UnknownProposer)?
        .try_output()?;
        if let Some((_, output_value)) =  step.extend_with(_bc_step_1, |fault| fault, from_p_msg).pop() {
            self.broadcast_instance_outputs.insert(self.our_id.clone(), output_value);
        }
        Ok(step.join(self.try_output()?))       
    }

    pub fn handle_message(&mut self, sender_id: &N, msg: Message) -> Result<Step<N>> {
        let bc_step = self
            .broadcast_instances
            .get_mut(sender_id)
            .ok_or(Error::UnknownSender)?
            .handle_message(sender_id, msg)?;
        let mut step = self.convert_step(sender_id, bc_step)?;
        let from_p_msg = |p_msg: Message| p_msg;
        let _bc_step_1 = self
        .broadcast_instances
        .get_mut(&self.our_id)//从 proposal_states 映射中获取当前节点（our_id）的 ProposalState 的可变引用。
        .ok_or(Error::UnknownProposer)?
        .try_output()?;
        if let Some((_, output_value)) =  step.extend_with(_bc_step_1, |fault| fault, from_p_msg).pop() {
            self.broadcast_instance_outputs.insert(self.our_id.clone(), output_value);
        }
        Ok(step.join(self.try_output()?))
    }

    pub fn netinfo(&self) -> &Arc<NetworkInfo<N>> {
        &self.netinfo
    }

    fn convert_step(&mut self, sender_id: &N, bc_step: BroadcastStep<N>) -> Result<Step<N>> {
        let from_p_msg = |p_msg: Message| p_msg;
        let mut step = Step::default();
        if let Some(value) = step.extend_with(bc_step, |fault| fault, from_p_msg).pop() {
            let (proposer_id, (digest, signature, _sub_block)) = value;
            if proposer_id.clone() == sender_id.clone() {
                // 手动查找是否存在相同的 proposer_id
                let pos = self.bc_signatures.iter().position(|(id, _)| *id == proposer_id);
                match pos {
                    Some(_) => return Err(Error::MultipleOutputValueReceived),
                    None => self.bc_signatures.push((proposer_id.clone(), (digest, signature))),
                }
            } else {
                return Err(Error::UnknownSender);
            }
            /*if proposer_id.clone() == sender_id.clone() {
                match self.bc_signatures.entry(proposer_id.clone()) {
                    btree_map::Entry::Vacant(entry) => {
                        entry.insert((digest, signature));
                    }
                    btree_map::Entry::Occupied(_) => {
                        return Err(Error::MultipleOutputValueReceived);
                    }
                }
            } else {
                // 通过包装在 Ok 中返回错误
                return Err(Error::UnknownSender);
            }*/
        }
        Ok(step) // 注意这里是 Ok 包装的 step
    }


    pub fn try_output(&mut self) -> Result<Step<N>>{
        let signed_count = self.bc_signatures.len();
        let step = Step::default();
        if signed_count < self.netinfo.num_nodes() - self.netinfo.num_faulty() {
            return Ok(step);
        } else {
            self.complete = true;
            //将此时的bc_signature的值填入self.step的output中。
            return Ok(step.with_output(self.bc_signatures.clone()));
        }   
    }
}


/*pub enum BroadcastSetOutput<N> {
    /// A contribution was accepted into the set.
    Contribution(
        N,
        #[derivative(Debug(format_with = "util::fmt_hex"))] Vec<u8>,
    ),
    /// The set is complete.
    Done,
} //枚举中有2个值，第一个值为contribution包括一个数组。第二个值为done。*/


/*pub fn handle_broadcast<F>(&mut self) -> Result<Step<N>>//输入参数需要与前面的handle_message中的输入参数对应
    {
        // 用于存储处理结果的 Step
        let mut step = Step::default();
        
        // 遍历所有的 Broadcast 实例
        for (proposer_id, broadcast_instance_opt) in self.broadcast_instances.iter_mut() {
            if let Some(broadcast_instance) = broadcast_instance_opt {
                // 直接访问 Broadcast 结构体中的字段
                if broadcast_instance.thresholdsignature.is_some() && broadcast_instance.sigstate == SigState::Complete(true) {
                    let root_hash = broadcast_instance.readys.get(proposer_id).unwrap_or(&Vec::new()).clone();
                    let signature = broadcast_instance.thresholdsignature.clone().unwrap();
    
                    // 更新 bc_signature
                    self.bc_signature.insert(proposer_id.clone(), (Some(root_hash), Some(signature)));
                }
            }
        }
        
        // 检查是否达到 N-f 个签名
        let signed_count = self.bc_signature.values().filter(|(_, sig)| sig.1.is_some()).count();
        if signed_count >= self.val_set.len() - self.val_set.faulty() {
            self.complete = true;
            //将此时的bc_signature的值填入self.step的output中。
            step.output = self.bc_signature.clone();
        }
        
        Ok(step)
    }

    fn convert_step(proposer_id: &N, prop_step: ProposalStep<N>) -> Step<N> {
        let from_p_msg = |p_msg: MessageContent| p_msg.with(proposer_id.clone());
        let mut step = Step::default();
        if let Some(value) = step.extend_with(prop_step, |fault| fault, from_p_msg).pop() {//判断ProposalStep<N>所对应的状态下是否有output
            let contribution = BroadcastSetOutput::Contribution(proposer_id.clone(), value);//提取output值，也就是value值
            self.contributions.insert(proposer_id.clone(), contribution);//将contribution放入到
        }
        step
    }//它整合了提议（prop_step）和提议者（proposer_id）的信息，生成了一个新的步骤（Step），用于进一步的共识操作。


    /*pub fn try_output(&mut self) -> Result<Step<N, S>, Error> {
        let mut step = Step::default();  // 假设 Step 是一个您已经定义好的类型

        let our_node_id = self.netinfo.our_id().clone();  // 假设您有一种方式来获取当前节点的 NodeId
        
        if let Some(state) = self.proposal_states.get(&our_id) {
            if let ProposalState::LeaderSelection_HasDecided(decision) = state {
                match decision {
                    Some(true) => {
                        self.decided = true;
                        step.output.push(SubsetOutput::Done);  // 假设 SubsetOutput::Done 是一个您已经定义好的枚举值
                    }
                    Some(false) => {
                        let new_state = ProposalState::LeaderSelection_Ongoing(/* 初始化参数 */);
                        self.proposal_states.insert(our_node_id, new_state);
                    }
                    None => {
                        // 如果没有决定，什么也不做
                    }
                }
            }
        }

        Ok(step)
    }*/

    /*fn convert_step(sender_id: &N, bc_step: Broadcast<N>) -> Step<N> {
        let from_p_msg= |p_msg: Message| p_msg;
        let mut step = Step::default();
        if let Some(value) = step.extend_with(bc_step, |fault| fault, from_p_msg).pop() {
            let  (proposer_id, (digest, signature) )= value;
            match self.bc_signatures.get(&sender_id) {
                Some((None, None)) => {
                    // Step 2: 将output_value的值 (N, (u8, Signature)) 插入到self.cbc_signatures的对应位置。
                    self.bc_signatures.insert(proposer_id.clone(), (digest, signature));
                }
                _ => {
                    return Err(Error::MultipleOutputValueReceived);
                }
            }
        }
        step
    }*/
    // 更改返回类型为 Result<Step<N>>

    // 检查是否有N - f个门限签名
    /*pub fn check_completion(&mut self) {
        let f = (self.val_set.len() - 1) / 3; // 假设Byzantine容错能力为f
        if self.bc_signature.1.len() >= self.val_set.len() - f {
            self.complete = true;
        }
    }*/
}*/

  // 初始化 bc_signature 为 None
        /*for proposer_id in val_set.all_ids() {
            bc_signatures.insert(proposer_id.clone(), (None, None));
        }

        // 初始化 broadcast_instances
        for proposer_id in val_set.all_ids() {
            let broadcast_instance = Broadcast::new(our_id.clone(), val_set.clone(), proposer_id.clone())
                .map_err(|e| Error::BroadcastError(e))?;
            broadcast_instances.insert(proposer_id.clone(), broadcast_instance); // 值设置为 Some(broadcast_instance)
        }*/
//可能还需要增加一个handle_message方法，该方法来判断收到的消息是来自于self.our_id的cbc的output还是来自其他validator的cbc的output
    //现在最为关键的问题是谁调用fn check_cbc_output 可以在proposal_state中做这件事情，把CBC和CBCset结合起来


    // This must be called with every message we receive from another node.
    // 这里的handle_message更加高级，当一条消息传来时，这个文件的handle_message会被触发，并调用cbc实例的handle_message 来进一步处理收到的消息
    //返回的是CBCset结构体的最新状态值（看是否有N-f个(proposer_id, (digest, signature))被插入到 self.cbc_signatures中）

    //可以想象一下，每个节点都会通过cbcset的propose来开启关于自己的cbc实例——也就是广播自己的实例。这样，每个节点都会运行N个cbc实例。
//因此，这一段相当于通过cbcset的propose开启了N个cbc实例。然后上层模块可以调用cbcset的propose来开启整个过程。
//现在的问题是，你怎么知道在本地管理的N个ConsistentBroadcast<N, S>的最新状态被存储到了self.broadcast_instances中？

    