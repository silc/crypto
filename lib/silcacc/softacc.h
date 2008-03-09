/*

  softacc.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcacc/Software Accelerator
 *
 * DESCRIPTION
 *
 * Software accelerator is a thread-pool system where computationally
 * expensive operations are executed in multiple threads for the purpose of
 * off-loading and balancing the computations across multiple cores and
 * processors.
 *
 * Software accelerator need not be registered with silc_acc_register
 * because it is registered automatically in SILC Crypto Toolkit, however
 * it must be initialized with silc_acc_init.
 *
 * ACCELERATORS
 *
 * Public key and private key accelerator:
 *
 * The software accelerator can accelerate public keys and private keys.
 * The public key and private key operations are executed in threads to
 * enhance the overall performance of the program and machine when multiple
 * public key and private key operations need to be executed at the same
 * time.  This can significantly improve performance, especially in server
 * applications.
 *
 * The accelerated public key and private key can be used with normal
 * SILC PKCS API.  Internally however the software accelerator is used.
 * The SilcSchedule must be given as argument to silc_acc_init if the
 * softacc is used to accelerate public keys and private keys.
 *
 * Ciphers:
 *
 * The software accelerator can accelerate ciphers.  The only supported
 * encryption mode is Counter Mode (CTR).  Ciphers with other encryption
 * modes cannot be accelerated.  The CTR mode is accelerated by pre-computing
 * the CTR key stream in threads.  This can significantly enhance both
 * encryption and decryption performance.
 *
 * The accelerated cipher can be used with normal SILC Cipher API.
 * Internally however the software accelerator is used.  Currently only
 * one limitation exist with accelerated ciphers and SILC Cipher API;  The
 * optional IV argument in silc_cipher_encrypt and silc_cipher_decrypt
 * cannot be used.  The IV must be set with silc_cipher_set_iv prior to
 * encrypting and decrypting.  Usually, this is not an issue for programmer.
 *
 * PERFORMANCE
 *
 * Ciphers:
 *
 * The AES is especially optimized in softacc.  Other ciphers can be used
 * as well, but their performance does not match that of the AES.
 *
 * On dual-core machine the default settings should give very good peak
 * performance.  In 2008, AES-128 was measured 2.0 Gbit/sec with default
 * settings.
 *
 * On 4-core and 8-core machines the default settings will not give the
 * best performance.  To get the best performance out, one must commit
 * system resources (RAM) for softacc.  In 2008, AES-128 was measured 5.68
 * Gbit/sec with cipher_blocks=65536 and cipher_streams=32 on 4-core
 * machine (Xeon 5160 3GHz) and 9.08 Gbit/sec with cipher_blocks=65536 and
 * cipher_streams=64 on 8-core machine (Xeon E5345 2.33GHz).  With default
 * settings you can expect 1-3 Gbit/sec reduction in peak performance.
 *
 * OPTIONS
 *
 * The following options can affect the behavior of the softacc and can be
 * given as argument to the silc_acc_init when initializing the softacc.
 *
 * "min_threads"
 *
 * The minimum amount of threads that the softacc will always run.  If
 * this isn't given the default number is 0 (does not start any threads
 * when initialized).
 *
 * "max_threads"
 *
 * The maximum amount of threads the software accelerator can use.  If
 * you are using the softacc only for accelerating public key and private
 * key operations this number should be the number of CPU cores in your
 * machine.  If you are using it also for accelerating ciphers this number
 * may need to be fairly large.  Each acclerated cipher will reserve
 * "cipher_threads" many threads from the softacc.  Always leave some
 * threads free for the public key and private key acceleration to work.
 * If this option is not given the default number is 4.
 *
 * "cipher_threads"
 *
 * The number of threads each accelerated cipher will use.  Note that,
 * each accelerated cipher will reserve this many threads from the softacc.
 * The "max_threads" will determine the final maximum number of threads
 * the softacc can use.  If the "max_threads" limit is reached no more
 * ciphers can be accelerated (also note that if this happens, public key
 * and private key acceleration does not work anymore).  The threads are
 * reserved as long as the cipher is accelerated.  If this option is not
 * given the default number is 2.
 *
 * "cipher_blocks"
 *
 * The number of cipher blocks the softacc will pre-compute.  Each cipher
 * block consumes 16 or 8 bytes of memory, depending on the size of the
 * actual cipher block size.  This value can be used to tweak the
 * performance of the softacc.  If this option is not given the default
 * number is 4096.  The number must be multiple of 16.
 *
 * "cipher_streams"
 *
 * The number of pre-computation streams each accelerated cipher will use.
 * Each stream will use "cipher_blocks" many blocks in the stream.  This
 * number can be used to tweak the performance of the softacc.  If this
 * option is not given the default number is 2 * "cipher_threads".
 *
 * EXAMPLE
 *
 * // Initialize the software accelerator.
 * silc_acc_init(SILC_SOFTACC, NULL, "min_threads", 2, "max_threads", 8, NULL);
 *
 * // Accelerate cipher
 * SilcCipher acc_cipher;
 *
 * acc_cipher = silc_acc_cipher(SILC_SOFTACC, cipher);
 * silc_cipher_set_key(acc_cipher, key, key_len, TRUE);
 * silc_cipher_set_iv(acc_cipher, iv);
 *
 * // Encrypt with the accelerated cipher
 * silc_cipher_encrypt(acc_cipher, src, dst, len, NULL);
 *
 * // Free accelerated cipher
 * silc_cipher_free(acc_cipher);
 *
 * // Free the original associated cipher
 * silc_cipher_free(cipher);
 *
 ***/

#ifndef SOFTACC_H
#define SOFTACC_H

/****s* silcacc/softacc
 *
 * NAME
 *
 *    silc_softacc
 *
 * DESCRIPTION
 *
 *    The software accelerator context.  It can be used when initializing
 *    the accelerator.  It may be used directly with the SILC Accelerator
 *    Interface after initialization also.
 *
 *    Softare accelerator need not be registered with silc_acc_register
 *    because it is registered automatically in SILC Crypto Toolkit, however
 *    it must be initialized.
 *
 *    The software accelerator must be initialized once per application.  If
 *    it is initialized again it will be uninitialized first automatically
 *    and then re-initialized.  When it is not needed anymore (usually when
 *    the program is ended) it must be uninitialized by calling the
 *    silc_acc_uninit.
 *
 * EXAMPLE
 *
 *    // Initialize the software accelerator.
 *    silc_acc_init(SILC_SOFTACC, "min_threads", 2, "max_threads", 8, NULL);
 *
 ***/
extern DLLAPI const SilcAcceleratorStruct silc_softacc;

/****d* silcacc/SILC_SOFTACC
 *
 * NAME
 *
 *    #define SILC_SOFTACC (SilcAccelerator)&softacc
 *
 * DESCRIPTION
 *
 *    Softacc context macro that can be used with silc_acc_init.
 *
 ***/
#define SILC_SOFTACC (SilcAccelerator)&silc_softacc

/****d* silcacc/SILC_SOFTACC_NAME
 *
 * NAME
 *
 *    #define SILC_SOFTACC_NAME "softacc"
 *
 * DESCRIPTION
 *
 *    The name of the software accelerator.
 *
 ***/
#define SILC_SOFTACC_NAME "softacc"

#endif /* SOFTACC_H */
