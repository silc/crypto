#ifndef __SILC_QUERIES_H
#define __SILC_QUERIES_H

#include "chat-protocols.h"
#include "queries.h"
#include "silc-servers.h"

/* Returns SILC_QUERY_REC if it's SILC query, NULL if it isn't. */
#define SILC_QUERY(query) \
	PROTO_CHECK_CAST(QUERY(query), QUERY_REC, chat_type, "SILC")
#define IS_SILC_QUERY(query) \
	(SILC_QUERY(query) ? TRUE : FALSE)
#define silc_query_find(server, name) \
	query_find(SERVER(server), name)

QUERY_REC *silc_query_create(const char *server_tag,
			     const char *nick, int automatic);
void silc_queries_init(void);
void silc_queries_deinit(void);

#endif