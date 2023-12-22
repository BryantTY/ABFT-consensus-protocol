Strong Provable Broadcast (SPB) Instance:

1) Each consensus $node_i$ at epoch $k$ creates a dictionary $D[i_k]$ with $n$ key-value pairs. Initially, each pair $D[i_k][j]$ (key: consensus $node j$'s id) has an empty tuple as a value. On receiving a 'CBC_SEND' message containing $node j$'s valid $cbc.echo.sshares.[j_s]$ at epcoh $k$, $node_i$ adds $j_s$ to $D[i_k][j]$. When $2f+1$ tuples in $D[i_k]$ are non-empty, $node_i$ sends $(i, ($'SPB_STORE'$, D[i_k]))$ to every consensus node.

2) Upon receiving $(j, ($'SPB_STORE'$, D[j_k]))$ from $node_j$, $node_i$ verifies $D[j_k]$'s validity, checking if $D[j_k]$ has $2f+1$ non-empty tuples representing CBC instances. If $D[j_k]$ is valid, implying $node_i$ received all cbc_echo_sshares, it signs $j_k$ using ecdsa_sign($SK[i]$) to create a signature share ($Sigs.i1$) and sends $(i, ($'SPB_STORED'$, Sigs.i1, j))$ to $node_j$.

3) $Node_i$, receiving 'SPB_STORED' for epoch $k$ from $node_j$, checks its validity using ecdsa_vrfy($PK[j]$, $i_k$, $Sigs.j1$). Valid messages are stored in $SPB.stage1.sshares.[i_k]$. Once 2f+1 valid shares are collected and stored in $SPB.stage1.sshares.[i_k]$, $node_i$ sends $(i, ($'SPB_LOCK'$, SPB.stage1.sshares.[i_k]))$ to every consensus node.

4) $Node_i$, receiving $(j, ($'SPB_LOCK'$, SPB.stage1.sshares.[j_k]))$, verifies the signatures in $SPB.stage1.sshares.[j_k]$ using ecdsa_vrfy. If valid, it signs $hash(j_k, SPB.stage1.sshares.[j_k])$ with ecdsa_sign($SK[i]$), creating $Sigs.i2$, and sends $(i, ($'SPB_LOCKED'$, Sigs.i2, j_k))$ to $node_j$.

5) On receiving a 'SPB_LOCKED' message for epoch $k$ from $node_j$, $node_i$ checks its validity with ecdsa_vrfy($PK[j], hash(i_k, SPB.stage1.sshares.[i_k]), Sigs.j2$). Valid messages are stored in $SPB.stage2.sshares.[i_k]$. If 2f+1 valid shares are collected, $node_i$ initiates the LEADER_ELECTION instance.
