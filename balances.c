#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

/* Usage: ./balances *.blk
 * Reads in a list of block files and outputs a table of public key hashes and
 * their balance in the longest chain of blocks. In case there is more than one
 * chain of the longest length, chooses one arbitrarily. */

/* If a block has height 0, it must have this specific hash. */
const hash_output GENESIS_BLOCK_HASH = {
	0x00, 0x00, 0x00, 0x0e, 0x5a, 0xc9, 0x8c, 0x78, 0x98, 0x00, 0x70, 0x2a, 0xd2, 0xa6, 0xf3, 0xca,
	0x51, 0x0d, 0x40, 0x9d, 0x6c, 0xca, 0x89, 0x2e, 0xd1, 0xc7, 0x51, 0x98, 0xe0, 0x4b, 0xde, 0xec,
};

struct blockchain_node {
	struct blockchain_node *parent;
	struct block b;
	int is_valid;
};

/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
};

/* Add or subtract an amount from a linked list of balances. Call it like this:
 *   struct balance *balances = NULL;
 *
 *   // reward_tx increment.
 *   balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);
 *
 *   // normal_tx increment and decrement.
 *   balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
 *   balances = balance_add(balances, &prev_transaction.dest_pubkey, -1);
 */
static struct balance *balance_add(struct balance *balances,
	struct ecdsa_pubkey *pubkey, int amount)
{
	struct balance *p;

	for (p = balances; p != NULL; p = p->next) {
		if ((byte32_cmp(p->pubkey.x, pubkey->x) == 0)
			&& (byte32_cmp(p->pubkey.y, pubkey->y) == 0)) {
			p->balance += amount;
			return balances;
		}
	}

	/* Not found; create a new list element. */
	p = malloc(sizeof(struct balance));
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;
}

// return 1 if a block's normal_tx is valid, otherwise return 0
int is_normal_tx_valid(struct blockchain_node *node)
{
	struct blockchain_node *temp;
	hash_output h1, h2;
	struct transaction *prev_transaction = NULL;
	// rule 5.1
	temp = node;
	while (temp->parent != NULL) {
		temp = temp->parent;
		transaction_hash(&temp->b.normal_tx, h1);
		transaction_hash(&temp->b.reward_tx, h2);
		if (byte32_cmp(node->b.normal_tx.prev_transaction_hash, h1) == 0) {
			prev_transaction = &temp->b.normal_tx;
			break;
		}
		else if (byte32_cmp(node->b.normal_tx.prev_transaction_hash, h2) == 0) {
			prev_transaction = &temp->b.reward_tx;
			break;
		}
	}
	if (prev_transaction == NULL)
		return 0;
	// rule 5.2
	if (transaction_verify(&temp->b.normal_tx, prev_transaction) != 1)
		return 0;
	// rule 5.3
	temp = node;
	while (temp->parent != NULL) {
		temp = temp->parent;
		if (byte32_cmp(temp->b.normal_tx.prev_transaction_hash, node->b.normal_tx.prev_transaction_hash) == 0)
			return 0;
	}

	return 1;
}

// return 1 if a block is valid, otherwise return 0
int is_valid(struct blockchain_node *node)
{
	hash_output h;
	block_hash(&node->b, h);

	// rule 1.1
	if (node->b.height == 0
		&& byte32_cmp(h, GENESIS_BLOCK_HASH) != 0)
		return 0;
	// rule 1.2
	if (node->b.height >= 1
		&& !(node->parent != NULL && is_valid(node->parent) == 1 && node->parent->b.height == node->b.height - 1))
		return 0;
	// rule 2
	if (hash_output_is_below_target(h) != 1)
		return 0;
	// rule 3
	if (!(node->b.reward_tx.height == node->b.height
		&& node->b.normal_tx.height == node->b.height))
		return 0;
	// rule 4
	if (byte32_is_zero(node->b.reward_tx.prev_transaction_hash) != 1
		|| byte32_is_zero(node->b.reward_tx.src_signature.r) != 1
		|| byte32_is_zero(node->b.reward_tx.src_signature.s) != 1)
		return 0;
	// rule 5
	if (byte32_is_zero(node->b.normal_tx.prev_transaction_hash) != 1
		&& is_normal_tx_valid(node) != 1)
		return 0;

	return 1;
}

// construct a blockchain_node from a block
void blockchain_node_init(struct blockchain_node *node, struct block *b)
{
	struct block parent;
	block_get_parent(&parent, b->prev_block_hash);
	memset(node, 0, sizeof(*node));

	node->b = *b;
}

// set the parent of a block chain node
void set_blockchain_relation(struct blockchain_node *node, struct blockchain_node block_nodes[], unsigned long block_chain_nodes_size)
{
	int i;
	hash_output h;
	for (i = 0; i < block_chain_nodes_size; i++) {
		block_hash(&block_nodes[i].b, h);
		if (byte32_cmp(h, node->b.prev_block_hash) == 0) {
			node->parent = &block_nodes[i];
			break;
		}
	}
	if (i == block_chain_nodes_size) {
		node->parent = NULL;
	}
}

// set the validation of a block chain node
void set_blockchain_validation(struct blockchain_node *node)
{
	node->is_valid = is_valid(node);
}

int main(int argc, char *argv[])
{
	int i;
	struct blockchain_node block_nodes[argc - 1];

	/* Read input block files. */
	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}

		/* TODO */
		/* Feel free to add/modify/delete any code you need to. */
		struct blockchain_node node;

		blockchain_node_init(&node, &b);
		block_nodes[i-1] = node;
	}

	/* Organize into a tree, check validity, and output balances. */
	/* TODO */

	unsigned long block_chain_nodes_size = (sizeof(block_nodes)/sizeof(block_nodes[0]));

	for (i = 0; i < block_chain_nodes_size; i++) {
		set_blockchain_relation(&block_nodes[i], block_nodes, block_chain_nodes_size);
	}

	for (i = 0; i < block_chain_nodes_size; i++) {
		set_blockchain_validation(&block_nodes[i]);
	}

	struct balance *balances = NULL, *p, *next;



	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	return 0;
}
