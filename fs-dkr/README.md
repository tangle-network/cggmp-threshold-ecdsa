# FS-DKR: One Round Distributed Key Rotation


## Intro
In this note we aim to re-purpose the [Fouque-Stern](https://hal.inria.fr/inria-00565274/document) Distributed Key Generation (DKG) to support a secure Distributed Key Refresh (DKR). As we claim, FS-DKR is well suited for rotation of [threshold ECDSA](https://eprint.iacr.org/2020/540.pdf) keys.



## Background
The FS-DKG protocol is a one round DKG based on Publicly Verifiable Secret Sharing (PVSS) and the [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem). There are two major security shortcomings to FS-DKG:
1. It introduces a factoring assumptions (DCRA)
2. it is insecure against rushing adversary

Rushing adversary is a common assumption in Multiparty Computation (MPC). In FS-DKG, an adversary waiting to receive messages from all other parties will be able to decide on the final public key. In the worst case it can lead to a rogue-key attack, giving full control of the secret key to the attacker. This is the main reason, in our opinion, why  FS-DKG, altough with prominent features, was over-looked for the past 20 years.
in this write-up we show how by adjusting FS-DKG to key rotation for threshold ecdsa the above shortcomings are avoided.

## Our Model
We use standard proactive security assumptions. The protocol will be run by $n$ parties. We assume honest majority, that is, number of corruptions is $t<=n/2$. The adversary is malicious, and rushing.
For communication, the parties have access to a broadcast channel (can be implemented via a bulletin board).
For threshold ECDSA, we focus on [GG20](https://eprint.iacr.org/2020/540.pdf) protocol, currently considered state of the art and most widely deployed threshold ecdsa scheme (e.g. [multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa), [tss-lib](https://github.com/binance-chain/tss-lib)). 

## How To Use
### Refresh a Key
Each party calls `RefreshMessage::distribute(key)` on their `LocalKey` and broadcasts the `RefreshMessage` while saving their new `DecryptionKey`. <br>
After recieving all the refresh messages each party calls `RefreshMessage::collect(..)` with a vector of all the refresh messages, a mutable reference to their own key, and their new `DecryptionKey`, This will validate all the refresh messages, and if all the proofs are correct it will update the local key to contain the new decryption keys of all the parties.

Example:
```rust
// All parties should run this
let mut party_i_key: LocalKey<_>;
let (party_i_refresh_message, party_i_new_decryption_key) = RefreshMessage::distribute(party_i_key);
broadcast(party_i_refresh_message);
let vec_refresh_messages = recv_from_broadcast();
RefreshMessage::collect(&vec_refresh_messages, &mut party_i_key, party_i_new_decryption_key, &[])?;
```

### Replacing a party
Each party that wants to join first generates a `JoinMessage` via `JoinMessage::distribute()` and broadcasts it to the current parties. <br>
The existing parties choose the index(who are they replacing) for the joining party.
Note that this part is delicate and needs to happen outside of the library because it requires some kind of mutual agreement, and you cannot trust the new party to communicate which party are they replacing. <br>
After agreeing on the index each party modifies the join message to contain the index `join_message.party_index = Some(index)`. <br>
Each existing party calls `RefreshMessage::replace(join_message, local_key)` with the join message and its own local key, this returns a refresh message and a new decryption key, just like in a Key Refresh, and they all broadcast the `RefreshMessage`. <br>
Each existing party recieves all the broadcasted refresh messages and calls `RefreshMessage::collect(..)` with a vector of all the refresh messages, a mutable reference to their own key, the new `DecryptionKey`, and a slice of all the join messages(`JoinMessage`) <br>
This will validate both the refresh messages and the join messages and if all the proofs are correct it will update the local key both as a refresh(new decryption keys) and replace the existing parties with the new ones. <br>
The new party calls `join_message.collect(..)` with the broadcasted `RefreshMessage` of the existing parties and all the join messages which returns a new `LocalKey` for the new party.

Example:
```rust
// PoV of the new party
let (join_message, new_party_decryption_key) = JoinMessage::distribute();
broadcast(join_message);
let new_party_index = recv_broadcast();
let vec_refresh_messages = recv_from_broadcast();
let new_party_local_key = join_message.collect(&vec_refresh_messages, new_party_decryption_key, &[])?;

// PoV of the other parties
let mut party_i_key: LocalKey<_>;
let mut join_message = recv_broadcast();
let new_index = decide_who_to_replace(&join_message);
broadcast(new_index);
assert!(recv_from_broadcast().iter().all(|index| index == new_index));
join_message.party_index = Some(new_index);
let (party_i_refresh_message, party_i_new_decryption_key) = RefreshMessage::replace(join_message, party_i_key)?;
broadcast(party_i_refresh_message);
let vec_refresh_messages = recv_from_broadcast();
RefreshMessage::collect(&vec_refresh_messages, &mut party_i_key, party_i_new_decryption_key, &[join_message])?;
```

## High-level Description of FS-DKG
Here we give a short description of the FS-DKG protocol.
FS-DKG works in one round. This round includes a single broadcast message from each party $P_j$. For Setup, we assume every party in the system has a public/private key pair for Paillier encryption scheme. 
At first, $P_j$ picks a random secret $s$ and secret shares it. $P_j$ publishes one set of size $t$ of commitment points $\textbf{A}$ corresponding to the polynomial coefficients: $A_i = a_iG$, and one set of $n$ commitment points $\textbf{S}$ corresponding to $n$ points on the polynomial: $S_i = \sigma_i G$. The points on the polynomial are also encrypted using the paillier keys of the receiving parties: $Enc_{pk_i}(\sigma_i)$. Finally, $P_j$ computes zero knowledge proofs $\pi_i$ to show that the paillier encryption for $P_i$ encrypts the same value commited in $S_i$. The ZK proof is a sigma protocol (can be made non-interactive using Fiat-Shamir) given in the original FS paper under the name proof of fairness. We [implemented it](https://github.com/ZenGo-X/fs-dkr/blob/main/src/proof_of_fairness.rs) under the same name.

Verification proceeds as follows. Each party $P_j$ verifies:
1. all broadcasted proofs of fairness 
2. all secret sharing schemes - computing the polynomial points "at the exponent"

The parties define the set $\mathcal{Q}$ to be the set of the first $t+1$ parties for which all checks passed. we now show a simple optimization on how each party computes its local secret key: Each party [maps its encrypted shares](https://github.com/ZenGo-X/fs-dkr/blob/main/src/lib.rs#L181) from $\{t,n\}$ to $\{\mathcal{Q},\mathcal{Q}\}$. It then homomorphically adds all the paillier ciphertext (which is an additive homomorphic scheme) and decrypts to get the local secret key. 


## Adjusting FS-DKG to DKR and threshold ECDSA
We will now highlight the adjustments required for FS-DKR.
In a key refresh protocol the parties start with their inputs equal to the outputs of a DKG done in the past or the output of previous DKR. Meaning, as opposed to FS-DKG protocol in which the inputs are pseudorandom such that the attacker can bias the output, for example in a rushing adversary attack, FS-DKR avoids this potential attack on FS-DKG because of the added restriction over the inputs of the attacker. Concretely, in the case the parties must reshare their DKG/DKR output secret share, all other parties already know a public commitment to the attacker secret share and can check for it.
Recall that FS-DKG is secure assuming Paillier is secure (what we called DCRA assumption). Moreover, we assumed a setup phase in which all parties generate paillier keys and share them. This fits well with threshold ECDSA: First, GG20 already requires us to assume Paillier security, therefore in this particular case, no new assumption is needed. The setup phase actually happens as part of GG20 DKG. We will use this to our advantage, running the FS-DKR using the GG20-DKG paillier keys.  Obviously because we need to refresh the paillier keys as well we will also add a step to FS-DKR to generate new paillier keys and prove they were generated correctly. This is a standard proof, that can be made non-interactive. See the [zk-paillier lib](https://github.com/ZenGo-X/zk-paillier/blob/master/src/zkproofs/correct_key_ni.rs) for an implementation. 

**Adding/Removing parties:** There is a clear distinction between parties with secret shares (”Senders”) and new parties (”Receivers”). The FS-DKR protocol therefore supports adding and removing parties in a natural way: Define $\mathcal{J}>t+1$ the subset of parties participating in the protocol. To remove an existing party $P_i$, other parties exclude it from the subset $\mathcal{J}$. To add a new party, we assume the parties in $\mathcal{J}$ are aware of the new party' paillier key. In that case, the parties in $\mathcal{J}$ assign an index $i$ to the new party and broadcast the PVSS messages to it. Removal of a party is simply done by not broadcasting the encrypted messages to it. If enough parties decide on that for a party index, they will not be able to reconstruct a rotated key.

**Identifiable Abort:** A nice property of FS-DKR is that if a party misbehaves all honest parties learn about it. This is due to the nature of PVSS used in the protocol. As GG20, our reference threshold ECDSA protocol, also have this property, it is important that identifiable abort can be guaranteed throughout the DKR as well. 

For completeness, Below is the FS-DKR protocol, written as FS-DKG with changes in red for DKR. ![](https://i.imgur.com/V50DfBz.png)
The protocol is implemented in the [ZenGo-X/fs-dkr repo](https://github.com/ZenGo-X/fs-dkr) (warning, the code is not audited yet).


## Related Work
Our main requirement from FS-DKR is minimal round-count. In FS-DKR the parties can pre-process all the data they need to send. Our main bottleneck is $\mathcal{O}(n^2)$ communication, which seems a standard cost in our context: It is the same asymptotic complexity as we have in GG20-DKG and GG20-Signing.

In this section we focus on alternative protocols for DKR. Three recent results come to mind. The first one, [CGGMP20](https://eprint.iacr.org/2021/060.pdf), is another threshold ECDSA protocol with a companion refresh protocol, see figure 6 in the paper. Their protocol has the most resemblance to FS-DKR, with few notable differences. First, while FS-DKR is publicly verifiable, CGGMP20-DKR current [version](https://eprint.iacr.org/2021/060/20210118:082423) suffers from a technichal issue with its Identifiable Abort (acknowledged by the authors). Second, the paillier keys used in the CGGMP20-DKR are the new ones, while in FS-DKR, we use the old ones, already known to all, which helps us save a round of communication. Finally, CGMMP20-DKR key refresh is done by adding shares of zero while in FS-DKR we re-share existing shares. Overall we treat the similarities between the protocols as a positive signal of validation for FS-DKR. 
A second protocol, by [Gurkan et. al.](https://eprint.iacr.org/2021/005), uses gossip for aggregating transcripts from the parties. However, their DKG is generating group elements secret shares and we need field elements secret shares for our threshold ECDSA. 
The third relevant work is Jens Groth' [Non interactive DKG and DKR](https://eprint.iacr.org/2021/339). There, instead of paillier encryption, they use El-Gamal based encryption scheme that offers forward security. Their DKR makes the assumption that the El-Gamal decryption keys are long-term and not rotated. This assumption seems crucial for the Groth-DKG construction.  In our context it means that we need to let the parties generate, store and use a new set of keypair,in addition to the Paillier keypair, and that this new keypair poses a security risk  against  the  classical  mobile  adversary,  which  our  model  does  not  allow. As opposed to Groth-DKR, FS-DKR is reusing the existing paillier keypair and rotate it as well. In terms of efficiency - there is no complexity analysis given in the paper, however, from inspection we estimate the asymptotic complexity is comparable to FS-DKR (quadratic in the number of parties).

## Acknowledgments
We thank Claudio Orlandi, Kobi Gurkan and Nikolaos Makriyannis for reviewing the note

