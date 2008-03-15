/*

  silcskr_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSKR_I_H
#define SILCSKR_I_H

#ifndef SILCSKR_H
#error "Do not include this header directly"
#endif

/* Internal representation of SilcSKRKey context. */
typedef struct {
  struct SilcSKRKeyStruct key;	           /* Key data */
  SilcInt32 refcnt;			   /* Reference counter */
} *SilcSKRKeyInternal;

/* Key Repository context */
struct SilcSKRObject {
  SilcSchedule scheduler;
  SilcMutex lock;		          /* Repository lock */
  SilcHashTable keys;			  /* All keys in repository */
};

/* Find context */
struct SilcSKRFindStruct {
  SilcHashTable constr;			   /* Search constraints */
};

/* Backwards support */
#define SilcSKRStatus SilcResult
#define SILC_SKR_OK SILC_OK
#define SILC_SKR_ERROR SILC_ERR
#define SILC_SKR_ALREADY_EXIST SILC_ERR_ALREADY_EXISTS
#define SILC_SKR_NOT_FOUND SILC_ERR_NOT_FOUND
#define SILC_SKR_NO_MEMORY SILC_ERR_OUT_OF_MEMORY
#define SILC_SKR_UNSUPPORTED_TYPE SILC_ERR_NOT_SUPPORTED

#endif /* SILCSKR_I_H */
