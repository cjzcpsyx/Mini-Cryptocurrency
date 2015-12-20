# Mini-Cryptocurrency
An implementation of a Bitcoin-like cryptocurrency, including validating blocks and transactions, organizing blocks into a blockchain, and computing the balance corresponding to accounts.
### Rules of a valid block
* If the block has height 0 (the “genesis block”), its SHA256 hash must be the hardcoded
value 0000000e5ac98c789800702ad2a6f3ca510d409d6cca892ed1c75198e04bdeec.
(Use the byte32_cmp function.) If a block has height ≥1, its parent must be a valid
block with a height that is 1 smaller.
* The hash of the block must be smaller than TARGET_HASH; i.e., it must start with 24 zero
bits. (Use the hash_output_is_below_target function.)
* The height of both of the block's transactions must be equal to the block's height.
* The reward_tx.prev_transaction_hash, reward_tx.src_signature.r, and
reward_tx.src_signature.s members must be zero—reward transactions are not
signed and do not come from another public key. (Use the byte32_zero function.)
* If normal_tx.prev_transaction_hash is zero, then there is no normal transaction
in this block. But if it is not zero:
* The transaction referenced by normal_tx.prev_transaction_hash must exist
as either the reward_tx or normal_tx of an ancestor block. (Use the
transaction_hash function.)
* The signature on normal_tx must be valid using the dest_pubkey of the previous
transaction that has hash value normal_tx.prev_transaction_hash. (Use the
transaction_verify function.)
* The coin must not have already been spent: there must be no ancestor block that
has the same normal_tx.prev_transaction_hash.
### Mining a new block
It is possible to steal coins of we can guess the private key that correspons to a public key.
```
/* Build on top of the head of the main chain. */
block_init(&newblock, &headblock);
/* Give the reward to us. */
transaction_set_dest_privkey(&newblock.reward_tx, mykey);
/* The last transaction was in block 4. */
transaction_set_prev_transaction(&newblock.normal_tx,
&block4.normal_tx);
/* Send it to us. */
transaction_set_dest_privkey(&newblock.normal_tx, mykey);
/* Sign it with the guessed private key. */
transaction_sign(&newblock.normal_tx, weakkey);
/* Mine the new block. */
block_mine(&newblock);
/* Save to a file. */
block_write_filename(&newblock, "myblock1.blk");
```
