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
#include <err.h>

#include "asymops.h"
#include "defines.h"
#include "compat.h"
#include "tweetnacl.h"
#include "utils.h"

void
asymcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf,
    struct hdr *hdr, FILE *key, FILE *skey)
{

        unsigned char pk[PUBKEYBYTES] = {0};
        unsigned char sk[SECKEYBYTES + ZEROBYTES] = {0};

        /* Read in the public and secret keys */
        get_keys(pk, sk, key, skey);

        if (crypto_box(ctext_buf, pad_ptext_buf, hdr->padded_len,
            hdr->nonce, pk, sk + ZEROBYTES) != 0)
                err(1, "Error encrypting data");

        /* Zap secret key */
        explicit_bzero(sk, sizeof(sk));
}

void
asymdecrypt(unsigned char *ptext_buf, unsigned char *ctext_buf,
    unsigned long long ctext_size, unsigned char *nonce, FILE *pkey, FILE *skey)
{
        unsigned char pk[PUBKEYBYTES] = {0};
        unsigned char sk[SECKEYBYTES + ZEROBYTES] = {0};

        get_keys(pk, sk, pkey, skey);

        if (crypto_box_open(ptext_buf, ctext_buf,
            ctext_size, nonce, pk, sk + ZEROBYTES) != 0)
                errx(1, "Error decrypting data");

        explicit_bzero(sk, sizeof(sk));
}

