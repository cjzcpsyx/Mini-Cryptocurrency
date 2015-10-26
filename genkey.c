#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common.h"

/* Usage: genkey FILENAME
 * Generate a key and write it to the file FILENAME. */

/* Interpret the 256 bits in buf as a private key and return an EC_KEY *. */
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

/* Generate a key using EC_KEY_generate_key. */
static EC_KEY *generate_key(void)
{
	EC_KEY *key;
	int rc;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		return NULL;
	rc = EC_KEY_generate_key(key);
	if (rc != 1) {
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}

int main(int argc, char *argv[])
{
	const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];

	unsigned char buf[32];
	int i;
	for (int j = 1443700000; j<1443701800; j++) {
		srand(j);
		for (i = 0; i < 32; i++) {
			buf[i] = rand() & 0xff;
		}
		key = generate_key_from_buffer(buf);
		key_write_filename(filename, key);

		key = key_read_filename(filename);

		BIGNUM *x = BN_new();
	    BIGNUM *y = BN_new();

	    if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), x, y, NULL)) {
	    	printf("%d\n", j);
	        BN_print_fp(stdout, x);
	    }
	}
	

	// key = generate_key();
	if (key == NULL) {
		fprintf(stderr, "error generating key\n");
		exit(1);
	}

	rc = key_write_filename(filename, key);
	if (rc != 1) {
		fprintf(stderr, "error saving key\n");
		exit(1);
	}

	EC_KEY_free(key);

	return 0;
}
