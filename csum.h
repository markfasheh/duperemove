#ifndef __CSUM_H__
#define __CSUM_H__

#include <stdio.h>

#define	DIGEST_LEN_MAX	32

extern unsigned int digest_len;

/* Init / debug */
int init_hash(void);
void debug_print_digest(FILE *stream, unsigned char *digest);

/* Checksums a single block in one go. */
void checksum_block(char *buf, int len, unsigned char *digest);

/* Keeping a 'running' checksum - we add data to it a bit at a time */
struct running_checksum;
struct running_checksum *start_running_checksum(void);
void add_to_running_checksum(struct running_checksum *c,
			     unsigned int len, unsigned char *buf);
void finish_running_checksum(struct running_checksum *c, unsigned char *digest);

#endif /* __CSUM_H__ */
