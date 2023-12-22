## Background
Contemporary BFT (Byzantine Fault Tolerant) consensus protocols predominantly utilize leader-selection methods. 
This approach, however, has notable limitations: 
Firstly, it results in unbalanced bandwidth usage. 
The leader node must broadcast its block to the remaining n-1 validator nodes, demanding significant bandwidth. 
Contrastingly, these validator nodes only need to send less data-intensive messages, 
either broadcasting (as in PBFT protocols) or sending (as in HotStuff protocols). 
Consequently, the leader node faces considerable bandwidth strain, limiting the overall throughput of the consensus protocol. 
Meanwhile, the bandwidth capacity of other validator nodes remains underutilized. 
Secondly, leader-selection methods presuppose (semi-)synchronous network environments 
where messages sent by a sender are guaranteed to reach a receiver within a specific time frame. 
This assumption becomes problematic in globally dispersed blockchain networks, 
rendering the timely delivery of messages across all geographically distributed nodes impractical.


## Inspiration
In 2015-2016, the Honey Badger (HB) BFT protocol emerged as a practical solution to these challenges. 
HB-BFT addresses these issues effectively: 
1) Each node produces and broadcasts its own sub-block, ensuring optimal bandwidth utilization, especially in the Reliable Broadcast (RBC) phase.
2) To accommodate the asynchronous nature of network environments, HB-BFT incorporates the Asynchronous Binary Agreement (ABA) sub-protocol, 
introducing randomness to avoid "FLP impossiblity" probelm.
3) It also employs the Asynchronous Common Subset (ACS) strategy for selecting a minimum of $2f+1$ sub-blocks from $2f+1$ nodes to achieve consensus.
This innovative paradigm shift in BFT protocol design enhances scalability and security beyond the capabilities of traditional (semi-)synchronous BFT protocols.


## Problems
Yet, Honey Badger BFT (HBBFT) and its derivatives are not without their flaws: 
1) An HBBFT epoch consists of two distinct phases: $n$ concurrent Reliable Broadcast (RBC) instances,
which are bandwidth-intensive, and $n$ concurrent Asynchronous Binary Agreement (ABA) instances, which are more bandwidth-efficient but time-consuming.
For HBBFT to progress to the next epoch, it must fully complete the current one.
This leads to a dichotomy within each epoch, oscillating between a bandwidth-heavy phase and a more efficient but slower phase.
Consequently, this results in underutilized bandwidth during the ABA phase.

2) A significant challenge arises in the RBC (or Consistent Broadcast, CBC) phase, characterized by its $O(n^3*m)$ communication complexity,
where '$m$' denotes the size of a sub-block shard and '$n$' ($n=3f+1$) the total number of nodes.
Each epoch involves each node broadcasting its sub-block of size '$M$' (with $m=3*M/n$),
assuming $2f+1$ sub-blocks are confirmed per epoch, resulting in a block size of $(2f+1)*M=(2f+1)*n*m/3$.
While scaling up either '$n$' or '$m$' could enhance HBBFT’s scalability by increasing the block size per epoch,
the $O(n^3*m)$ communication complexity makes this impractical.

3) The time-intensive nature of the n parallel ABA instances significantly hampers throughput.
To achieve higher throughput, increasing the block size per epoch seems logical,
but this exacerbates the communication complexity issue inherent in the RBC phase.


## What it does
We propose three significant enhancements:

1) Utilizing a concurrent operational mechanism from Dumbo_NG (2022 CCS conference), we integrate three parallel-running strategies.
First, broadcast instances (RBC or CBC) operate concurrently.
Second, stages 1 and 2 of HBBFT run in parallel.
Furthermore, Dumbo_NG introduces a novel ABA protocol (from the 2022 PODC conference paper) reducing the traditional ABA's time consumption.
This amalgamation significantly decreases HBBFT protocol latency.

2) We have proposed a mechanism to lower communication complexity from $O(n^3*m)$ to $O(n^2*m)$ in asynchronous BFT protocols.
3) To this end, we employing Verifiable Information Dispersal (VID) twice and separate the roles of consensus nodes in block dispersal and retrieval. 

(i) VID uses erasure-coding encode (ECen) to divide a message $M$ into $n$ pieces, 
where any $k$ pieces can reconstruct $M$ through erasure-coding decode (ECde).
Each node encodes $M$ into $n$ shards (each $3*M/n$ in size) and sends each shard to a corresponding node, 
thus broadcasting $M$ at a total cost of $3M$, compared to $n*M$ in traditional methods. 
As every node broadcasts $M$, total bandwidth for $n$ pieces of $M$ is $3M*n (i.e., O(n^2*m))$, 
a significant reduction from the traditional $3M*n^2 (O(n^2*m))$. 
However, each node still needs to reconstruct the complete block of each epoch, which maintains a recovery cost of $O(n^3*m)$. 

(ii) Our innovation lies in the second use of VID and a decoupling strategy. 
We introduce a new group of computation nodes (nc nodes) responsible for block recovery each epoch. 
The connection between consensus and computation nodes is via VID. 
When a consensus node completes an RBC or CBC instance for $M$, it only possesses a shard "$m$" of $M$. 
This shard with $m$ size is input into ECen, producing $n_c$ smaller shards, which are then distributed to corresponding computation nodes. 
Each consensus node, receiving $n$ shards per epoch, will only need $3m*n$ bandwidth to broadcast these shards, 
and collectively, $n$ consensus nodes only use a total of $3m*n^2$ bandwidth.
