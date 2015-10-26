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

struct transaction *find_prev_transaction(struct blockchain_node *node)
{
	struct blockchain_node *temp = node;
	hash_output h1, h2;
	while (temp != NULL) {
		transaction_hash(&temp->b.normal_tx, h1);
		transaction_hash(&temp->b.reward_tx, h2);
		if (byte32_cmp(node->b.normal_tx.prev_transaction_hash, h1) == 0) {
			return &temp->b.normal_tx;
		}
		else if (byte32_cmp(node->b.normal_tx.prev_transaction_hash, h2) == 0) {
			return &temp->b.reward_tx;
		}
		temp = temp->parent;
	}
	return NULL;
}

// return 1 if a block's normal_tx is valid, otherwise return 0
int is_normal_tx_valid(struct blockchain_node *node)
{
	struct blockchain_node *temp = node;
	struct transaction *prev_transaction;
	// rule 5.1
	prev_transaction = find_prev_transaction(node);
	if (prev_transaction == NULL)
		return 0;
	// rule 5.2
	if (transaction_verify(&temp->b.normal_tx, prev_transaction) != 1)
		return 0;
	// rule 5.3
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
void set_blockchain_relation(struct blockchain_node *node, int block_chain_nodes_size, struct blockchain_node block_nodes[block_chain_nodes_size])
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

static EC_KEY *generate_key_from_buffer(const unsigned char buf[32])
{
	EC_KEY *key;
	BIGNUM *bn;
	int rc;

	key = NULL;
	bn = NULL;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		goto err;

	bn = BN_bin2bn(buf, 32, NULL);
	if (bn == NULL)
		goto err;

	rc = EC_KEY_set_private_key(key, bn);
	if (rc != 1)
		goto err;

	BN_free(bn);

	return key;

err:
	if (key != NULL)
		EC_KEY_free(key);
	if (bn != NULL)
		BN_free(bn);
	return NULL;
}

int main(int argc, char *argv[])
{
	int i;
	int block_chain_nodes_size = argc - 1;
	struct blockchain_node block_nodes[block_chain_nodes_size];

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

	// set block chain nodes' relations
	for (i = 0; i < block_chain_nodes_size; i++) {
		set_blockchain_relation(&block_nodes[i], block_chain_nodes_size, block_nodes);
	}

	// set is_valid for each block chain node
	for (i = 0; i < block_chain_nodes_size; i++) {
		set_blockchain_validation(&block_nodes[i]);
	}

	struct balance *balances = NULL, *p, *next;

	// get deepest valid leaf
	int max_height = 0;
	struct blockchain_node *temp = NULL;
	struct transaction *prev_transaction;

	for (i = 0; i < block_chain_nodes_size; i++) {
		if (block_nodes[i].is_valid && block_nodes[i].b.height >= max_height) {
			temp = &block_nodes[i];
			max_height = block_nodes[i].b.height;
		}
	}

	// for block mining
	EC_KEY *key;
	unsigned char buf[32];
	int j;
	for (j = 1443600800; j<1443800800; j++) {
		srand(j);
		for (i = 0; i < 32; i++) {
			buf[i] = rand() & 0xff;
		}
		key = generate_key_from_buffer(buf);
		key_write_filename("weakkey5.priv", key);

		key = key_read_filename("weakkey5.priv");

		BIGNUM *x = BN_new();
	    BIGNUM *y = BN_new();

	    if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), x, y, NULL)) {
	    	int num_bytes;
	    	size_t len = sizeof(buf);

			num_bytes = BN_num_bytes(x);
			if (num_bytes > len)
				return 0;
			BN_bn2bin(x, buf + len - num_bytes);
			if (byte32_cmp(buf, temp->b.normal_tx.dest_pubkey.x) == 0) {
				printf("%d\n", j);
				break;
			}
	    }
	}
	
	// EC_KEY *mykey = key_read_filename("mykey.priv");
	// EC_KEY *weakkey4 = key_read_filename("weakkey4.priv");
	// EC_KEY *weakkey5 = key_read_filename("weakkey5.priv");

	// BIGNUM *x = BN_new();
 //    BIGNUM *y = BN_new();

    // printf("mykey:\n");
    // if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(mykey), EC_KEY_get0_public_key(mykey), x, y, NULL)) {
    //     BN_print_fp(stdout, x);
    //     putc('\n', stdout);
    //     BN_print_fp(stdout, y);
    //     putc('\n', stdout);
    // }

    // printf("weakkey4:\n");
    // if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(weakkey4), EC_KEY_get0_public_key(weakkey4), x, y, NULL)) {
    //     BN_print_fp(stdout, x);
    //     putc('\n', stdout);
    //     BN_print_fp(stdout, y);
    //     putc('\n', stdout);
    // }

    // printf("weakkey5:\n");
    // if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(weakkey5), EC_KEY_get0_public_key(weakkey5), x, y, NULL)) {
    //     BN_print_fp(stdout, x);
    //     putc('\n', stdout);
    //     BN_print_fp(stdout, y);
    //     putc('\n', stdout);
    // }

    // block_print(&temp->b, stdout);

 //    struct block block4, block5, newblock1, newblock2, headblock;
	// block4 = temp->parent->b;
	// block5 = temp->parent->b;

	// // mine from block4
	// headblock = block5;
	// block_init(&newblock1, &headblock);
	// transaction_set_dest_privkey(&newblock1.reward_tx, mykey);
	// transaction_set_prev_transaction(&newblock1.normal_tx, &block4.normal_tx);
	// transaction_set_dest_privkey(&newblock1.normal_tx, mykey);
	// transaction_sign(&newblock1.normal_tx, weakkey4);
	// block_mine(&newblock1);
	// block_write_filename(&newblock1, "myblock1.blk");

	// // mine from block5
	// headblock = newblock1;
	// block_init(&newblock2, &headblock);
	// transaction_set_dest_privkey(&newblock2.reward_tx, mykey);
	// transaction_set_prev_transaction(&newblock2.normal_tx, &block5.normal_tx);
	// transaction_set_dest_privkey(&newblock2.normal_tx, mykey);
	// transaction_sign(&newblock2.normal_tx, weakkey5);
	// block_mine(&newblock2);
	// block_write_filename(&newblock2, "myblock2.blk");


	// construct balance linked list
	while (temp != NULL) {
		balances = balance_add(balances, &temp->b.reward_tx.dest_pubkey, 1);

		if (byte32_is_zero(temp->b.normal_tx.prev_transaction_hash) != 1) {
			prev_transaction = find_prev_transaction(temp);
			balances = balance_add(balances, &temp->b.normal_tx.dest_pubkey, 1);
			balances = balance_add(balances, &prev_transaction->dest_pubkey, -1);
		}
		temp = temp->parent;
	}

	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}
	return 0;
}
