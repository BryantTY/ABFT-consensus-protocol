## Challenges Encountered:

I've verified that my protocol adheres to the key properties (agreement, totality, liveness) required by atomic broadcast protocol. The most tricky part for me is to fully implement the complete consensus protocol. I have finished the most rudimentary version of CBC protocol, Leader_selection protocol in Rust. However, I still do not achieve the Rust version of SPB protocol, SPEED VALIDATED AGREEMENT protocol and Dumbo_NG protocol, which also only has python version from [here](https://github.com/fascy/Dumbo_NG)
Another part is that I need to implement the retrival process operated by computation node group. I need to finish the code parts in Rust. 

## Accomplishments that we're proud of

We've achieved two key advancements in consensus protocols:
1) Enhanced scalability, with communication complexity reduced from $O(n^3*m)$ to $O(n^2*m)$.
2) Optimized bandwidth utilization across nodes, enabled by concurrent broadcast instances and Dumbo_NG framework, enhancing network throughput and reducing latency.

## Insights Gained:

Our protocol integrates three core internal strategies to enhance performance while maintaining security and decentralization. These include communication complexity reduction, hardware optimization, and parallel sub-protocol execution. Distinct from external approaches like layer 2 and sharding, our internal solutions offer potential synergy with these methods for a more robust consensus protocol.

## Future Directions for Scalable Asynchronous BFT Protocol:

Research Focus:
1) Refining transaction propagation to surpass the inefficiency of gossip protocols. We're designing a new protocol to ensure transaction inclusion in the blockchain by reaching only 3/2 of the consensus nodes on average.
2) Exploring zero-knowledge proofs and multi-party computation for efficient block recovery, aiming to minimize computational costs.

Code Development:
1) Completion of sub-protocols within the consensus framework.
2) Integration of these sub-protocols through a central control mechanism.
3) Rigorous testing of the overall consensus protocol.
