/*

  silcschedule_i.h.

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSCHEDULE_I_H
#define SILCSCHEDULE_I_H

#include "silcincludes.h"

/* Schedule FD structure. Includes the file descriptors that the scheduler
   will listen. This is given as argument to the silc_select function. */
typedef struct {
  uint32 fd;			/* The file descriptor (or handle on WIN32) */
  uint16 events;		/* Mask of task events, if events is 0 then
				   the fd must be omitted. */
  uint16 revents;		/* Returned events mask */
} *SilcScheduleFd;

#endif