#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2008 Pekka Riikonen
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

AUTOMAKE_OPTIONS = 1.0 no-dependencies foreign

check_PROGRAMS = test_silcmp

TESTS = test_silcmp

LIBS = $(SILC_COMMON_LIBS)
LDADD = -L.. -L../.. -lsct

include $(top_srcdir)/Makefile.defines.in
