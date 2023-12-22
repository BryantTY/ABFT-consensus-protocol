## LEADER_ELECTION Instance:

1) Consensus $node_i$ generates a threshold signature share $tss_i[k0]$ for epoch $k$ at round $0$ by signing $hash(k, 0)$ using def encrypt() and sends $(i, ($'ELECTION'$, tss_i[k0], k, 0))$ to every consensus node.

2) When $node_i$ receives a message $(j, ($'ELECTION'$, tss_j[k0], k, 0))$ from $node_j$, it validates $tss_j[k0]$ with def verify_ciphertext(). If valid, $tss_j[k0]$ is added to $TSset_i[k0]$. Once $TSset_i[k0]$ has $f+1$ valid shares, $node_i$ combines them with def combine_shares() to form a threshold signature $TS[k0]$, converted to an integer $L$ via $int(TS[k0])$%$n$. $L$, ranging from $0$ to $n-1$, is the elected node's id. $Node_i$ then proceeds to the SPEED VALIDATED AGREEMENT instance.
