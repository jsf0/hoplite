#define	VERSION	"0.1"

#define FILENAME_SIZE   255
#define EXT     ".enc"
#define SIGNEXT ".signed"
#define PUB     "-encryption-pubkey.curve25519"
#define SEC     "-encryption-secretkey.curve25519"
#define PUBSIGN "-signing-pubkey.ed25519"
#define SECSIGN "-signing-secretkey.ed25519"

#define	ARGON2_T	3	/* Number of default iterations */
#define ARGON2_MEM	448	/* Default RAM used in MiB */
#define ARGON2_P	4	/* Default number of threads */
#define MIN_ROUNDS      3	/* Minimum iterations */
#define MAX_ROUNDS      1024	/* Maximum iterations */
#define	MIN_MEM		56	/* Minimum RAM in MiB */
#define	MAX_MEM		64000	/* Maximum RAM in MiB */
#define MIN_THREADS	2	/* Minimum number of threads for Argon2 */
#define	MAX_THREADS	256	/* Maxmimum number of threads for Argon2 */

#define IDSIZE  	128
#define B64NAMESIZE     192
#define PUBKEYBYTES     crypto_box_PUBLICKEYBYTES
#define SECKEYBYTES     crypto_box_SECRETKEYBYTES
#define SYMKEYBYTES     crypto_secretbox_KEYBYTES
#define NONCEBYTES      crypto_box_NONCEBYTES
#define ZEROBYTES       crypto_box_ZEROBYTES
#define SIGNSKEYBYTES   crypto_sign_SECRETKEYBYTES
#define SIGNPKEYBYTES   crypto_sign_PUBLICKEYBYTES
#define	PASSPHRASE_SIZE	512
