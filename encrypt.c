/*
 * Copyright (c) 2020 Joseph Fierro <joseph.fierro@logosnetworks.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/mman.h>

#include <err.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>

#include "hoplite.h"
#include "defines.h"
#include "asymops.h"
#include "symops.h"
#include "tweetnacl.h"
#include "compat.h"
#include "utils.h"

void
hoplite_encrypt(FILE *infile, FILE *key, FILE *skey, char *filename,
	   int alg, long long rounds, long long mem, long long threads)
{
	unsigned long long ptext_size, ctext_size = 0;
	unsigned char *pad_ptext_buf, *ctext_buf = NULL;
	FILE *outfile = NULL;
	struct hdr *hdr = NULL;
	
	/* Allocate the struct that will be the file header */
	hdr = malloc(sizeof(struct hdr));
	if (hdr == NULL)
		err(1, "Error allocating hdr");
	
	/* Generate random nonce. This is safe because TweetNaCL 
	 * uses XSalsa20, which has a 192 bit nonce. 
	 */
	randombytes(hdr->nonce, NONCEBYTES);

	/* Get plaintext size and create buffer for it */
	ptext_size = get_size(infile);
	hdr->padded_len = (ptext_size + ZEROBYTES);
	if ((pad_ptext_buf = malloc(hdr->padded_len)) == NULL)
		err(1, "Couldn't allocate pad ptext buf");

	/* 0-pad first ZEROBYTES of pad_ptext_buf & read in message */
	memset(pad_ptext_buf, 0, ZEROBYTES);
	read_infile(infile, pad_ptext_buf + ZEROBYTES, ptext_size);

	ctext_size = (hdr->padded_len);
	if ((ctext_buf = malloc(ctext_size)) == NULL)
		err(1, "Error creating ctext buffer");

	if (alg == 1) {
	/* Asymmetric encryption */
		hdr->rounds = 0;
		hdr->mem = 0;
		hdr->threads = 0;
		hdr->alg = 1;
		asymcrypt(ctext_buf, pad_ptext_buf, hdr, key, skey);
	} else if (alg == 2) {
	/* Symmetric encryption */
		hdr->rounds = rounds;
		hdr->mem = mem;
		hdr->threads = threads;
		hdr->alg = 2;
		symcrypt(ctext_buf, pad_ptext_buf, hdr);
	} else { 
		errx(1, "Don't know what to do");
	}

	/* Zero and free the plaintext as soon as we're done with it */
	explicit_bzero(pad_ptext_buf, hdr->padded_len);
	free(pad_ptext_buf);

	/* Append the extension to the filename */
	if (portable_strlcat(filename, EXT, FILENAME_SIZE) >= FILENAME_SIZE)
		errx(1, "Filename too long");

	/* Write the encrypted file */
	write_enc(outfile, hdr, ctext_buf, filename);
	free(ctext_buf);
	free(hdr);
	printf("Encryption successful\n");
}
