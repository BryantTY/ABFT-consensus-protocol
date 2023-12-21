use std::collections::BTreeMap;
use std::sync::Arc;
//use hex_fmt::HexFmt;
use rand::Rng;
use threshold_crypto::Signature; 
//use log::debug;
// 如果您使用的是`rand` crate
use crate::{ConsensusProtocol, NetworkInfo, NodeIdT, SessionIdT, Fault};
use crate::subset::BaSessionId;
use super::{ConsistentBroadcast, Step as ConsistentBroadcastStep};
use crate::broadcast::merkle::Digest;
use super::{Error, FaultKind, Message, Result};

#[derive(Debug, Clone)] 
pub struct ConsistentBroadcastSet<N, S> {
    our_id: N,
    session_id: S,
    netinfo: Arc<NetworkInfo<N>>,
    cbc_signatures: Vec<(N, (Digest, Signature))>, // 使用 Option 类型
    consistent_broadcast_instances: BTreeMap<N, ConsistentBroadcast<N, S>>, // 包含 N 个元素
    //contributions: BTreeMap<N, #[derivative(Debug(format_with = "util::fmt_hex"))] (N, (u8, Signature)),
    complete: bool,
}

pub type Step<N> = crate::Step<Message<N>, Vec<(N, (Digest, Signature))>, N, FaultKind>;

impl<N: NodeIdT, S: SessionIdT> ConsensusProtocol for ConsistentBroadcastSet<N, S> {
    type NodeId = N;
    type Input  = Vec<(N, (Digest, Signature))>;  // 提供的RBC实例的输入信息
    type Output =  Vec<(N, (Digest, Signature))>; // bc_signature
    type Message = Message<N>; //需要对消息类型进行修改
    type Error = Error;
    type FaultKind = FaultKind;

    fn handle_input<R: Rng>(&mut self, input: Self::Input, _rng: &mut R) -> Result<Step<N>> {
        self.propose(input)//这里input应该填什么类型！！！！！！
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
        self.complete
    }

    fn our_id(&self) -> &Self::NodeId {
        //&self.our_id
        &self.our_id
    }
}

impl <N: NodeIdT, S: SessionIdT> ConsistentBroadcastSet<N, S> {
    pub fn new(our_id: N, netinfo: Arc<NetworkInfo<N>>, session_id: S) -> Result<Self>
    {
        let cbc_signatures: Vec<(N, (Digest, Signature))> = Vec::new();
        let mut consistent_broadcast_instances: BTreeMap<N, ConsistentBroadcast<N, S>> = BTreeMap::new();
        for (proposer_idx, proposer_id) in netinfo.all_ids().enumerate() {
            let _ba_id = BaSessionId {
                subset_id: session_id.clone(),
                proposer_idx: proposer_idx as u32,
            };
            //our_id: N, val_set: V, netinfo: Arc<NetworkInfo<N>>, proposer_id: N
            consistent_broadcast_instances.insert(
                proposer_id.clone(),
                ConsistentBroadcast::new(netinfo.clone(), session_id.clone(), our_id.clone(), proposer_id.clone()).expect("consistent broadcast instance"),
            );
        }

        Ok(Self {
            our_id,
            session_id,
            netinfo,
            cbc_signatures,
            consistent_broadcast_instances,
            complete: false,
        })
    }
    /// propose的目的是激活自己的CBC实例。propose会被更高层级的模块调用（也就是有N-f个broadcast实例输出了门限签名）。
    /// propose需要得到的是自己CBC实例的输出。因此，propose方法需要将自己CBC实例的输出作为handle_output实例的输入，去调用handle_output。
    /// handle_output的作用就是接收CBC实例的输出，并将CBC实例的输出insert到cbc_signatures中。并判断complete的条件是否达到。
    /// 因此，我们需要确定的是CBC实例是否有输出，如果一个CBC实例已经有了输出，就需要去调用handle_output方法。
    /// 这是对自己的cbc进行启动
    pub fn propose(&mut self, value: Vec<(N, (Digest, Signature))>) -> Result<Step<N>> {
        if !self.netinfo.is_validator() {
            return Ok(Step::default());
        }
        //debug!("{} proposing {:0.10}", self, HexFmt(&value));//这是一个调试语句，用于输出当前节点正在提交哪个提案
        //这一步需要进行修改。我需要从Broadcast结构体中抽取出thresholdsignature中的值，如果有值的话。
        //如果有的话，就将这个抽取出来的值放入到 bc_signature中。然后调用try_output方法
        let cbc_step = self
            .consistent_broadcast_instances
            .get_mut(self.netinfo.our_id())//从 proposal_states 映射中获取当前节点（our_id）的 ProposalState 的可变引用。
            .ok_or(Error::UnknownProposer)?//这里需要修改，因为我们需要提取的是与self.our_id相同的proposer_id的CBC
            .propose(value)?;//相当于启动自己的PRBC实例。并将该实例的step最新状态赋值给prop_step
        //提取prop_step中可能有的output到现有的subset的step状态中
            // 执行 step.handle_output() 方法
        let step = Self::convert_step(self, &self.our_id.clone(), cbc_step);
        Ok(step.join(self.try_output()?))//这是对自己的cbc进行启动
    }//可以想象一下，每个节点都会通过cbcset的propose来开启关于自己的cbc实例——也就是广播自己的实例。这样，每个节点都会运行N个cbc实例。
    //因此，这一段相当于通过cbcset的propose开启了N个cbc实例。然后上层模块可以调用cbcset的propose来开启整个过程。
    //现在的问题是，你怎么知道在本地管理的N个ConsistentBroadcast<N, S>的最新状态被存储到了self.broadcast_instances中？

    //可能还需要增加一个handle_message方法，该方法来判断收到的消息是来自于self.our_id的cbc的output还是来自其他validator的cbc的output
    //现在最为关键的问题是谁调用fn check_cbc_output 可以在proposal_state中做这件事情，把CBC和CBCset结合起来


     /// This must be called with every message we receive from another node.
     /// 这里的handle_message更加高级，当一条消息传来时，这个文件的handle_message会被触发，并调用cbc实例的handle_message 来进一步处理收到的消息
     /// 返回的是CBCset结构体的最新状态值（看是否有N-f个(proposer_id, (digest, signature))被插入到 self.cbc_signatures中）
     pub fn handle_message(&mut self, sender_id: &N, msg: Message<N>) -> Result<Step<N>> {
        let Message { proposer_id, .. } = msg.clone();
        let cbc_step = self
            .consistent_broadcast_instances
            .get_mut(&msg.proposer_id)
            .ok_or(Error::UnknownProposer)?
            .handle_message(sender_id, msg)?;
        let step = Self::convert_step(self, &proposer_id, cbc_step);
        Ok(step.join(self.try_output()?))
    }

    fn convert_step(&mut self, proposer_id: &N, cbc_step: ConsistentBroadcastStep<N>) -> Step<N> {
        let from_p_msg = |p_msg: Message<N>| p_msg;
        let mut step = Step::default();
        if let Some(value) = step.extend_with(cbc_step, |fault| fault, from_p_msg).pop() {
            let (prop_id, (digest, signature)) = value;
            if prop_id != proposer_id.clone() {
                let fault_kind = FaultKind::NonProposer;
                return Fault::new(proposer_id.clone(), fault_kind).into();
            } else if self.cbc_signatures.iter().any(|(id, _)| id == &prop_id) {
                return step;
            } else {

                self.cbc_signatures.push((prop_id.clone(), (digest, signature)));//在Rust中，一个不可变引用不能用来更改它指向的数据。这是Rust设计的一部分，旨在保证内存安全和避免数据竞争。
                return step;
            }
        }
        step
    }

    pub fn try_output(&mut self) -> Result<Step<N>>{
        let signed_count = self.cbc_signatures.len();
        //signed_count = self.cbc_signatures.values().filter(|(_, (_, sig))| sig.1.is_some()).count();
        let mut step = Step::default();
        if signed_count < self.netinfo.num_nodes() - self.netinfo.num_faulty() {
            return Ok(step);
        } else {
            self.complete = true;
            //将此时的bc_signature的值填入self.step的output中。
            step = step.with_output(self.cbc_signatures.clone());
            return Ok(step);
        }   
    }
}

    /*pub fn check_cbc_output(&mut self) -> Result<Step<N>> {
        let from_cbc_msg = |cbc_msg: Message| cbc_msg.with(proposer_id.clone());
        let mut step = Step::default();
        let mut errors = Vec::new();  // 用于存储可能出现的错误
    
        for (proposer_id, consistent_broadcast_instance) in self.consistent_broadcast_instances.iter_mut() {
            // 假设 cbc_step 是从 consistent_broadcast_instance 中获取的
            let cbc_step = consistent_broadcast_instance.step()?;  // 这里是一个假设的方法调用，您应该替换为实际的调用
    
            if let Some(output_value) = step.extend_with(cbc_step, |fault| fault, from_cbc_msg).pop() {
                match step.handle_output(output_value) {
                    Ok(_) => (),
                    Err(e) => errors.push(e),
                }
            }
        }
    
        if errors.is_empty() {
            Ok(step)
        } else {
            // 处理或返回错误。这里只是一个简单的示例，您可能需要更详细的错误处理。
            Err(errors[0].clone())
        }
    }*/
    
    /*pub fn check_cbc_output(&mut self) -> Result<Step<N>> {
        let from_cbc_msg = |cbc_msg: Message| cbc_msg.with(proposer_id.clone());
        let mut step = Step::default();
        //对每一个cbc实例的step中的output值进行查看，如果some(output)有返回值，则调用handle_output方法。
        for (proposer_id, consistent_broadcast_instance) in self.consistent_broadcast_instances.iter_mut() {
            if let Some(output_value) = step.extend_with(cbc_step, |fault| fault, from_cbc_msg).pop() {
                Ok(step.handle_output(output_value)?)
            }
            step
        }
    }*/
    //这里可能需要设计一个handle_all_ids_output方法。
    //然后，根据输入参数的cb


    /*pub fn handle_output(&mut self,  output_value: (proposer_id, (u8_value, signature))) -> Result<Step<N>> {
        //step 1: 检查self.cbc_signatures中键为output_value: (N, (u8, Signature)>中的N位置的值是否为（None,None）,如果是，则执行step 2，如果不是，则返回错误：multipleoutput_valuereceived
        let (proposer_id, (u8_value, signature)) = output_value;
        match self.cbc_signatures.get(&proposer_id) {
            Some((None, None)) => {
                // Step 2: 将output_value的值 (N, (u8, Signature)) 插入到self.cbc_signatures的对应位置。
                self.cbc_signatures.insert(proposer_id.clone(), (u8_value, signature));
            }
            _ => {
                return Err(Error::MultipleOutputValueReceived);
            }
        }
        Ok(step.join(self.try_output()?))
    }*/


   
        
        
        /*for (proposer_id, consistent_broadcast_instance_opt) in self.broadcast_instances.iter_mut() {
            if let Some(consistent_broadcast_instance) = consistent_broadcast_instance_opt {
                // 直接访问 Broadcast 结构体中的字段
                if consistent_broadcast_instance.c_final.is_some() && broadcast_instance.decided == true {
                    let doc_hash = consistent_broadcast_instance.value_map_hash.clone().unwrap();
                    let signature = consistent_broadcast_instance.thresholdsignature.clone().unwrap();
    
                    // 更新 bc_signature
                    self.cbc_signatures.insert(proposer_id.clone(), (Some(doc_hash), Some(signature)));
                }
            }
        }*/



    //这是用来验证每一个本地管理的CBC实例是否有输出，如果有，则将每个CBC实例的output放入到self.cbc_signatures中的对应位置
    /*pub fn handle_output<F>(&mut self) -> Result<Step<N>>//输入参数需要与前面的handle_message中的输入参数对应
    {
        // 用于存储处理结果的 Step
        let mut step = Step::default();
        
        // 遍历所有的 Broadcast 实例
        for (proposer_id, consistent_broadcast_instance_opt) in self.broadcast_instances.iter_mut() {
            if let Some(consistent_broadcast_instance) = consistent_broadcast_instance_opt {
                // 直接访问 Broadcast 结构体中的字段
                if consistent_broadcast_instance.c_final.is_some() && broadcast_instance.decided == true {
                    let doc_hash = consistent_broadcast_instance.value_map_hash.clone().unwrap();
                    let signature = consistent_broadcast_instance.thresholdsignature.clone().unwrap();
    
                    // 更新 bc_signature
                    self.cbc_signatures.insert(proposer_id.clone(), (Some(doc_hash), Some(signature)));
                }
            }
        }
        
        // 检查是否达到 N-f 个签名
        let signed_count = self.cbc_signatures.values().filter(|(_, (_, sig))| sig.1.is_some()).count();
        if signed_count >= self.netinfo.len() - self.netinfo.faulty() {
            self.complete = true;
            //将此时的bc_signature的值填入self.step的output中。
            step.output = self.cbc_signatures.clone();
        }
        
        Ok(step)
    }*/

    // 假设traits.rs在同一个crate中
// 或其他导入根据您的具体情况

// An output with an accepted contribution or the end of the set.
/*#[derive(Derivative, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derivative(Debug)]
pub enum ConsistentBroadcastSetOutput<N> {
    /// A contribution was accepted into the set.
    Contribution(
        N,
        #[derivative(Debug(format_with = "util::fmt_hex"))] (N, (u8, Signature)),
    ),
    /// The set is complete.
    Done,
} //枚举中有2个值，第一个值为contribution包括一个数组。第二个值为done。*/

