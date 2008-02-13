/* SILC PGP library tests */

#include "silccrypto.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcRng rng;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*pgp*,*pkcs1*,*asn1*,*rsa*,*dsa*");
  }

  silc_crypto_init(NULL);
  rng = silc_rng_alloc();
  silc_rng_init(rng);

  SILC_LOG_DEBUG(("Load private key"));
  if (!silc_pkcs_load_private_key("seckey.prv", "foobar", 6,
				  SILC_PKCS_ANY, &private_key))
    goto err;

  SILC_LOG_DEBUG(("Load public key"));
  if (!silc_pkcs_load_public_key("pubkey.asc", SILC_PKCS_ANY,  &public_key))
    goto err;

  silc_rng_free(rng);
  silc_crypto_uninit();

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
