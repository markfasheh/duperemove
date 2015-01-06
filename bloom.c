/*
 *  Copyright (c) 2012, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

/*
 * Refer to bloom.h for documentation on the public interfaces.
 */

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bloom.h"
#include "csum.h"

static int bloom_check_add(struct bloom * bloom,
                           void * buffer, int len, int add)
{
	if (bloom->ready == 0) {
		fprintf(stderr, "bloom is not initialized!\n");
		return -1;
	}

	int hits = 0;

	unsigned char digest[DIGEST_LEN_MAX];
	checksum_block(buffer, len, digest);

	register unsigned int a = ((unsigned int*)digest)[0];
	register unsigned int b = ((unsigned int*)digest)[1];

	register unsigned int x;
	register unsigned int i;
	register unsigned int byte;
	register unsigned int mask;
	register unsigned char c;

	/*
	 * We are using another way to reduce hashing
	 * See http://www.eecs.harvard.edu/~kirsch/pubs/bbbf/esa06.pdf
	 */
	for (i = 0; i < bloom->hashes; i++) {
		x = (a + i*b) % bloom->bits;
		byte = x >> 3;
		c = bloom->bf[byte];
		mask = 1 << (x % 8);

		if (c & mask) {
			hits++;
		} else {
			if (add) {
				bloom->bf[byte] = c | mask;
			}
		}
	}

	/* element already in (or collision) */
	if (hits == bloom->hashes) {
		return 1;
	}

	return 0;
}

/* See http://en.wikipedia.org/wiki/Bloom_filter#Optimal_number_of_hash_functions */
int bloom_init(struct bloom * bloom, int entries, double error)
{
	bloom->ready = 0;

	if (entries < 1 || error == 0) {
		return 1;
	}

	bloom->entries = entries;
	bloom->error = error;

	double num = log(bloom->error);
	double denom = 0.480453013918201; /* ln(2)^2 */
	bloom->bpe = -(num / denom);

	double dentries = (double)entries;
	bloom->bits = (int)(dentries * bloom->bpe);

	if (bloom->bits % 8) {
		bloom->bytes = (bloom->bits / 8) + 1;
	} else {
		bloom->bytes = bloom->bits / 8;
	}

	bloom->hashes = (int)ceil(0.693147180559945 * bloom->bpe);  /* ln(2) */

	bloom->bf = (unsigned char *)calloc(bloom->bytes, sizeof(unsigned char));
	if (bloom->bf == NULL) {
		return 1;
	}

	bloom->ready = 1;
	return 0;
}


int bloom_check(struct bloom * bloom, void * buffer, int len)
{
	return bloom_check_add(bloom, buffer, len, 0);
}


int bloom_add(struct bloom * bloom, void * buffer, int len)
{
	return bloom_check_add(bloom, buffer, len, 1);
}


void bloom_print(struct bloom * bloom)
{
	printf("bloom at %p\n", (void *)bloom);
	printf(" ->entries = %d\n", bloom->entries);
	printf(" ->error = %f\n", bloom->error);
	printf(" ->bits = %d\n", bloom->bits);
	printf(" ->bits per elem = %f\n", bloom->bpe);
	printf(" ->bytes = %d\n", bloom->bytes);
	printf(" ->hash functions = %d\n", bloom->hashes);
}


void bloom_free(struct bloom * bloom)
{
	if (bloom->ready) {
		free(bloom->bf);
	}
	bloom->ready = 0;
}
