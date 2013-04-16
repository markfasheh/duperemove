#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <mhash.h>

#include "csum.h"

static MHASH td;

#define	HASH_FUNC	MHASH_SHA256

unsigned int digest_len = 0;

void checksum_block(char *buf, int len, unsigned char *digest)
{
	td = mhash_init(HASH_FUNC);
	if (td == MHASH_FAILED)
		abort();

	mhash(td, buf, len);
	mhash_deinit(td, digest);
}

int init_hash(void)
{
	digest_len = mhash_get_block_size(HASH_FUNC);
	if (!digest_len)
		return 1;

	if (digest_len == 0 || digest_len > DIGEST_LEN_MAX)
		abort();

	return 0;
}

void debug_print_digest(FILE *stream, unsigned char *digest)
{
	int i;

	for (i = 0; i < digest_len; i++)
		fprintf(stream, "%.2x", digest[i]);
}

struct running_checksum {
	MHASH	td;
	unsigned char	digest[DIGEST_LEN_MAX];
};

struct running_checksum *start_running_checksum(void)
{
	struct running_checksum *c = calloc(1, sizeof(struct running_checksum));

	if (c)
		c->td = mhash_init(HASH_FUNC);

	return c;
}

void add_to_running_checksum(struct running_checksum *c,
			     unsigned int len, unsigned char *buf)
{
	mhash(c->td, buf, len);
}

void finish_running_checksum(struct running_checksum *c, unsigned char *digest)
{
	mhash_deinit(c->td, digest);
}
