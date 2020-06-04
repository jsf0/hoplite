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
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "symops.h"
#include "defines.h"
#include "compat.h"
#include "readpassphrase.h"
#include "argon2.h"
#include "tweetnacl.h"

extern int global_rpp_flags;

static void derive_key(struct hdr *, char *, unsigned char *);

void
symcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf, struct hdr *hdr)
{
	char pass[PASSPHRASE_SIZE] = {0};
	char pass2[PASSPHRASE_SIZE] = {0};
	unsigned char symkey[SYMKEYBYTES] = {0};

	/* Read in and confirm passphrase */
	if (!readpassphrase("Enter new passphrase: ", pass, sizeof(pass), global_rpp_flags))
		err(1, "Error getting passphrase");

	/* Only confirm passphrase if we're requiring a tty. This way we
	 * skip this when using stdin to make it easier to pipe in a passphrase
	 */
	if (global_rpp_flags == RPP_REQUIRE_TTY) {
		if (!readpassphrase("Confirm new passphrase: ", pass2, sizeof(pass2), global_rpp_flags)) {
                    explicit_bzero(pass, sizeof(pass));
		    explicit_bzero(pass2, sizeof(pass2));
		    err(1, "Error confirming passphrase");
		}
        	if (timingsafe_bcmp(pass, pass2, sizeof(pass)) != 0) {
		    explicit_bzero(pass, sizeof(pass));
	            explicit_bzero(pass2, sizeof(pass2));	
                    errx(1, "Passphrases do not match");
		}
        }

	/* Zero the extra passphrase buffer, derive the key, then zero the
	 * other passphrase buffer too
	 */
	explicit_bzero(pass2, sizeof(pass2));

	derive_key(hdr, pass, symkey);

	explicit_bzero(pass, sizeof(pass));

	/* Encrypt */
	if (crypto_secretbox(ctext_buf, pad_ptext_buf, hdr->padded_len,
	    hdr->nonce, symkey) != 0)
		errx(1, "Error encrypting message");

	/* Zero the key */
	explicit_bzero(symkey, sizeof(symkey));
}

void
symdecrypt(unsigned char *ptext_buf, unsigned char *ctext_buf, struct hdr *hdr)
{
        char pass[512] = {0};
        unsigned char symkey[SYMKEYBYTES] = {0};

	/* Read in passphrase */
	if (!readpassphrase("Enter passphrase: ", pass, sizeof(pass), global_rpp_flags))
                err(1, "Error getting passphrase");

	/* Derive the key, then zero the passphrase */
	derive_key(hdr, pass, symkey);
	explicit_bzero(pass, sizeof(pass));

	/* Decrypt */
        if (crypto_secretbox_open(ptext_buf, ctext_buf, hdr->padded_len,
            hdr->nonce, symkey) != 0)
                errx(1, "Error decrypting data");

	/* Zero the key */
	explicit_bzero(symkey, sizeof(symkey));

}

void
derive_key(struct hdr *hdr, char *pass, unsigned char *symkey)
{
	/* Derive symmetric key from passphrase. Note that the salt in
	 * this case is just the nonce we generated earlier. It is long,
	 * random, and unique per message, so this is safe to use here
	 */
	if (argon2i_hash_raw(hdr->rounds, hdr->mem, hdr->threads, pass, strlen(pass), hdr->nonce,
                sizeof(hdr->nonce), symkey, SYMKEYBYTES) != 0)
		errx(1, "Argon2 could not derive key");
}
