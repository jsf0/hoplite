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
#include <string.h>
#include <stdlib.h>

#include "hoplite.h"
#include "defines.h"
#include "asymops.h"
#include "symops.h"
#include "tweetnacl.h"
#include "compat.h"
#include "utils.h"

void
hoplite_decrypt(FILE *infile, FILE *pkey, FILE *skey, char *filename)
{
	unsigned char *ctext_buf = NULL;
	unsigned char *ptext_buf = NULL;
	FILE *outfile = NULL;
	struct hdr *hdr = NULL;

	hdr = malloc(sizeof(struct hdr));
	if (hdr == NULL)
		err(1, "Error allocating hdr");
	
	read_hdr(hdr, infile);

	if ((ctext_buf = malloc(hdr->padded_len)) == NULL)
		err(1, "Error creating ctext_buf");
	if (fread(ctext_buf, 1, hdr->padded_len, infile) != hdr->padded_len)
		errx(1, "Error reading in ciphertext");
	if ((ptext_buf = malloc(hdr->padded_len)) == NULL)
		err(1, "Error creating ptext_buf");

	if (hdr->alg == 1) {
		if (pkey == NULL)
		    errx(1, "Must provide sender's public key");
		if (skey == NULL) 
		    errx(1, "Must provide recipient's secret key");
		asymdecrypt(ptext_buf, ctext_buf, hdr->padded_len, hdr->nonce,
	    	pkey, skey);
	} else if (hdr->alg == 2) {
		symdecrypt(ptext_buf, ctext_buf, hdr);
	} else {
		errx(1, "Don't know what to do");
	}
	free(ctext_buf);

	filename[strlen(filename) - strlen(EXT)] = 0;

	outfile = fopen(filename, "w");
	fwrite(ptext_buf + ZEROBYTES, hdr->padded_len - ZEROBYTES, 1, outfile); 

	explicit_bzero(ptext_buf, hdr->padded_len);
	free(ptext_buf);
	fclose(outfile);
	free(hdr);
	printf("Decryption successful\n");
}
