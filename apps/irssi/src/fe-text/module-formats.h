#include "formats.h"

enum {
	TXT_MODULE_NAME,

        TXT_LASTLOG_TOO_LONG,
	TXT_LASTLOG_START,
	TXT_LASTLOG_END,

        TXT_REFNUM_NOT_FOUND,
        TXT_WINDOW_TOO_SMALL,
        TXT_CANT_HIDE_LAST,
	TXT_CANT_HIDE_STICKY_WINDOWS,
        TXT_CANT_SHOW_STICKY_WINDOWS,
        TXT_WINDOW_NOT_STICKY,
        TXT_WINDOW_SET_STICKY,
        TXT_WINDOW_UNSET_STICKY
};

extern FORMAT_REC gui_text_formats[];