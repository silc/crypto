/*

  server_backup.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

SILC_TASK_CALLBACK(silc_server_protocol_backup_done);

/* Backup router */
typedef struct {
  SilcServerEntry server;
  bool local;
} SilcServerBackupEntry;

/* Holds IP address and port of the primary router that was replaced
   by backup router. */
typedef struct {
  SilcIDIP ip;
  uint16 port;
  SilcServerEntry server;	/* Backup router that replaced the primary */
} SilcServerBackupReplaced;

/* Backup context */
struct SilcServerBackupStruct {
  SilcServerBackupEntry *servers;
  uint32 servers_count;
  SilcServerBackupReplaced **replaced;
  uint32 replaced_count;
};

typedef struct {
  uint8 session;
  bool connected;
  SilcServerEntry server_entry;
} SilcServerBackupProtocolSession;

/* Backup resuming protocol context  */
typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  bool responder;
  uint8 type;
  uint8 session;
  SilcServerBackupProtocolSession *sessions;
  uint32 sessions_count;
  long start;
} *SilcServerBackupProtocolContext;

/* Sets the `backup_server' to be one of our backup router. This can be
   called multiple times to set multiple backup routers. If `local' is
   TRUE then the `backup_server' is in the local cell, if FALSE it is
   in some other cell. */

void silc_server_backup_add(SilcServer server, SilcServerEntry backup_server,
			    bool local)
{
  int i;

  if (!server->backup)
    server->backup = silc_calloc(1, sizeof(*server->backup));

  for (i = 0; i < server->backup->servers_count; i++) {
    if (!server->backup->servers[i].server) {
      server->backup->servers[i].server = backup_server;
      server->backup->servers[i].local = local;
      return;
    }
  }

  i = server->backup->servers_count;
  server->backup->servers = silc_realloc(server->backup->servers,
					 sizeof(*server->backup->servers) *
					 (i + 1));
  server->backup->servers[i].server = backup_server;
  server->backup->servers[i].local = local;
  server->backup->servers_count++;
}

/* Returns the first backup router context. Returns NULL if we do not have
   any backup servers. */

SilcServerEntry silc_server_backup_get(SilcServer server)
{
  SilcServerEntry backup_router;
  int i;

  if (!server->backup)
    return NULL;

  for (i = 0; i < server->backup->servers_count; i++) {
    if (server->backup->servers[i].server) {
      backup_router = server->backup->servers[i].server;
      server->backup->servers[i].server = NULL;
      return backup_router;
    }
  }

  return NULL;
}

/* Deletes the backup server `server_entry. */

void silc_server_backup_del(SilcServer server, 
			    SilcServerEntry server_entry)
{
  int i;

  if (!server->backup)
    return ;

  for (i = 0; i < server->backup->servers_count; i++) {
    if (server->backup->servers[i].server == server_entry) {
      server->backup->servers[i].server = NULL;
      return;
    }
  }
}

/* Marks the IP address and port from the `server_id' as  being replaced
   by backup router indicated by the `server'. If the router connects at
   a later time we can check whether it has been replaced by an backup
   router. */

void silc_server_backup_replaced_add(SilcServer server, 
				     SilcServerID *server_id,
				     SilcServerEntry server_entry)
{
  int i;
  SilcServerBackupReplaced *r = silc_calloc(1, sizeof(*r));;

  if (!server->backup)
    server->backup = silc_calloc(1, sizeof(*server->backup));
  if (!server->backup->replaced) {
    server->backup->replaced = 
      silc_calloc(1, sizeof(*server->backup->replaced));
    server->backup->replaced_count = 1;
  }

  SILC_LOG_DEBUG(("********************************"));
  SILC_LOG_DEBUG(("Replaced added"));

  memcpy(&r->ip, &server_id->ip, sizeof(server_id->ip));
  //r->port = server_id->port;
  r->server = server_entry;

  for (i = 0; i < server->backup->replaced_count; i++) {
    if (!server->backup->replaced[i]) {
      server->backup->replaced[i] = r;
      return;
    }
  }

  i = server->backup->replaced_count;
  server->backup->replaced = silc_realloc(server->backup->replaced,
					  sizeof(*server->backup->replaced) *
					  (i + 1));
  server->backup->replaced[i] = r;
  server->backup->replaced_count++;
}

/* Checks whether the IP address and port from the `server_id' has been
   replaced by an backup router. If it has been then this returns TRUE
   and the bacup router entry to the `server' pointer if non-NULL. Returns
   FALSE if the router is not replaced by backup router. */

bool silc_server_backup_replaced_get(SilcServer server,
				     SilcServerID *server_id,
				     SilcServerEntry *server_entry)
{
  int i;

  SILC_LOG_DEBUG(("***********************************************"));

  if (!server->backup || !server->backup->replaced)
    return FALSE;

  for (i = 0; i < server->backup->replaced_count; i++) {
    if (!server->backup->replaced[i])
      continue;
    SILC_LOG_HEXDUMP(("IP"), server_id->ip.data, server_id->ip.data_len);
    SILC_LOG_HEXDUMP(("IP"), server->backup->replaced[i]->ip.data, 
		     server->backup->replaced[i]->ip.data_len);
    if (!memcmp(&server->backup->replaced[i]->ip, &server_id->ip,
		sizeof(server_id->ip))) {
      if (server_entry)
	*server_entry = server->backup->replaced[i]->server;
      SILC_LOG_DEBUG(("REPLACED"));
      return TRUE;
    }
  }

  SILC_LOG_DEBUG(("NOT REPLACED"));
  return FALSE;
}

/* Deletes a replaced host by the set `server_entry. */

void silc_server_backup_replaced_del(SilcServer server,
				     SilcServerEntry server_entry)
{
  int i;

  if (!server->backup || !server->backup->replaced)
    return;

  for (i = 0; i < server->backup->replaced_count; i++) {
    if (!server->backup->replaced[i])
      continue;
    if (server->backup->replaced[i]->server == server_entry) {
      silc_free(server->backup->replaced[i]);
      server->backup->replaced[i] = NULL;
      return;
    }
  }
}

/* Broadcast the received packet indicated by `packet' to all of our backup 
   routers. All router wide information is passed using broadcast packets. 
   That is why all backup routers need to get this data too. It is expected
   that the caller already knows that the `packet' is broadcast packet. */

void silc_server_backup_broadcast(SilcServer server, 
				  SilcSocketConnection sender,
				  SilcPacketContext *packet)
{
  SilcServerEntry backup;
  SilcSocketConnection sock;
  SilcBuffer buffer;
  SilcIDListData idata;
  int i;

  if (!server->backup || server->server_type != SILC_ROUTER)
    return;

  SILC_LOG_DEBUG(("Broadcasting received packet to backup routers"));

  buffer = packet->buffer;
  silc_buffer_push(buffer, buffer->data - buffer->head);

  for (i = 0; i < server->backup->servers_count; i++) {
    backup = server->backup->servers[i].server;

    if (!backup || backup->connection == sender || 
	server->backup->servers[i].local == FALSE)
      continue;

    idata = (SilcIDListData)backup;
    sock = backup->connection;

    silc_packet_send_prepare(sock, 0, 0, buffer->len); 
    silc_buffer_put(sock->outbuf, buffer->data, buffer->len);
    silc_packet_encrypt(idata->send_key, idata->hmac_send, 
			sock->outbuf, sock->outbuf->len);

    SILC_LOG_HEXDUMP(("Broadcasted packet, len %d", sock->outbuf->len),
		     sock->outbuf->data, sock->outbuf->len);

    /* Now actually send the packet */
    silc_server_packet_send_real(server, sock, FALSE);
  }
}

/* A generic routine to send data to all backup routers. If the `sender'
   is provided it will indicate the original sender of the packet and the
   packet won't be resent to that entity. The `data' is the data that will
   be assembled to packet context before sending. The packet will be
   encrypted this function. If the `force_send' is TRUE the data is sent
   immediately and not put to queue. If `local' is TRUE then the packet
   will be sent only to local backup routers inside the cell. If false the
   packet can go from one cell to the other. This function has no effect
   if there are no any backup routers. */

void silc_server_backup_send(SilcServer server,
			     SilcServerEntry sender,
			     SilcPacketType type,
			     SilcPacketFlags flags,
			     unsigned char *data,
			     uint32 data_len,
			     bool force_send,
			     bool local)
{
  SilcServerEntry backup;
  SilcSocketConnection sock;
  int i;

  if (!server->backup || server->server_type != SILC_ROUTER)
    return;

  SILC_LOG_DEBUG(("Start"));

  for (i = 0; i < server->backup->servers_count; i++) {
    backup = server->backup->servers[i].server;
    if (!backup)
      continue;

    if (sender == backup)
      continue;

    if (local && server->backup->servers[i].local == FALSE)
      continue;

    sock = backup->connection;
    silc_server_packet_send(server, backup->connection, type, flags, 
			    data, data_len, force_send);
  }
}

/* Same as silc_server_backup_send but sets a specific Destination ID to
   the packet. The Destination ID is indicated by the `dst_id' and the
   ID type `dst_id_type'. For example, packets destined to channels must
   be sent using this function. */

void silc_server_backup_send_dest(SilcServer server,
				  SilcServerEntry sender,
				  SilcPacketType type,
				  SilcPacketFlags flags,
				  void *dst_id,
				  SilcIdType dst_id_type,
				  unsigned char *data,
				  uint32 data_len,
				  bool force_send,
				  bool local)
{
  SilcServerEntry backup;
  SilcSocketConnection sock;
  int i;

  if (!server->backup || server->server_type != SILC_ROUTER)
    return;

  SILC_LOG_DEBUG(("Start"));

  for (i = 0; i < server->backup->servers_count; i++) {
    backup = server->backup->servers[i].server;
    if (!backup)
      continue;

    if (sender == backup)
      continue;

    if (local && server->backup->servers[i].local == FALSE)
      continue;

    sock = backup->connection;
    silc_server_packet_send_dest(server, backup->connection, type, flags, 
				 dst_id, dst_id_type, data, data_len, 
				 force_send);
  }
}

/* Processes incoming RESUME_ROUTER packet. This can give the packet
   for processing to the protocol handler or allocate new protocol if
   start command is received. */

void silc_server_backup_resume_router(SilcServer server, 
				      SilcSocketConnection sock, 
				      SilcPacketContext *packet)
{
  uint8 type, session;
  int ret;

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      sock->type == SILC_SOCKET_TYPE_UNKNOWN)
    return;

  SILC_LOG_DEBUG(("Start"));

  ret = silc_buffer_unformat(packet->buffer,
			     SILC_STR_UI_CHAR(&type),
			     SILC_STR_UI_CHAR(&session),
			     SILC_STR_END);
  if (ret < 0)
    return;
  
  /* If the backup resuming protocol is active then process the packet
     in the protocol. */
  if (sock->protocol && sock->protocol->protocol &&
      sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_BACKUP) {
    SilcServerBackupProtocolContext ctx = sock->protocol->context;
    int i;

    ctx->type = type;

    SILC_LOG_DEBUG(("********************************"));
    SILC_LOG_DEBUG(("Continuing protocol, type %d", type));

    if (type != SILC_SERVER_BACKUP_RESUMED &&
	type != SILC_SERVER_BACKUP_RESUMED_GLOBAL) {
      for (i = 0; i < ctx->sessions_count; i++) {
	if (session == ctx->sessions[i].session) {
	  ctx->session = session;
	  silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
	  return;
	}
      }
    } else {
      silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
      return;
    }

    SILC_LOG_DEBUG(("Bad resume router packet"));
    return;
  }

  /* We don't have protocol active. If we are router and the packet is 
     coming from our primary router then lets check whether it means we've
     been replaced by an backup router in my cell. This is usually received
     immediately after we've connected to our primary router. */

  if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
      server->router == sock->user_data &&
      type == SILC_SERVER_BACKUP_REPLACED) {
    /* We have been replaced by an backup router in our cell. We must
       mark our primary router connection disabled since we are not allowed
       to use it at this moment. */
    SilcIDListData idata = (SilcIDListData)sock->user_data;

    SILC_LOG_DEBUG(("We are replaced by an backup router in this cell"));
    idata->status |= SILC_IDLIST_STATUS_DISABLED;
    return;
  }

  if (type == SILC_SERVER_BACKUP_START ||
      type == SILC_SERVER_BACKUP_START_GLOBAL) {
    /* We have received a start for resuming protocol. */
    SilcServerBackupProtocolContext proto_ctx;

    proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
    proto_ctx->server = server;
    proto_ctx->sock = sock;
    proto_ctx->responder = TRUE;
    proto_ctx->type = type;
    proto_ctx->session = session;
    proto_ctx->start = time(0);

    SILC_LOG_DEBUG(("Starting backup resuming protocol as responder"));

    /* Run the backup resuming protocol */
    silc_protocol_alloc(SILC_PROTOCOL_SERVER_BACKUP,
			&sock->protocol, proto_ctx, 
			silc_server_protocol_backup_done);
    silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
  }
}

/* Timeout task callback to connect to remote router */

SILC_TASK_CALLBACK(silc_server_backup_connect_to_router)
{
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcServer server = sconn->server;
  int sock;

  SILC_LOG_DEBUG(("Connecting to router %s:%d", sconn->remote_host,
		  sconn->remote_port));

  /* Connect to remote host */
  sock = silc_net_create_connection(server->config->listen_port->local_ip,
				    sconn->remote_port,
				    sconn->remote_host);
  if (sock < 0) {
    silc_schedule_task_add(server->schedule, 0,
			   silc_server_backup_connect_to_router,
			   context, 2, 0, SILC_TASK_TIMEOUT, 
			   SILC_TASK_PRI_NORMAL);
    return;
  }

  /* Continue with key exchange protocol */
  silc_server_start_key_exchange(server, sconn, sock);
}

/* Constantly tries to reconnect to a primary router indicated by the
   `ip' and `port'. The `connected' callback will be called when the
   connection is created. */

void silc_server_backup_reconnect(SilcServer server,
				  const char *ip, uint16 port,
				  SilcServerConnectRouterCallback callback,
				  void *context)
{
  SilcServerConnection sconn;

  sconn = silc_calloc(1, sizeof(*sconn));
  sconn->server = server;
  sconn->remote_host = strdup(ip);
  sconn->remote_port = port;
  sconn->callback = callback;
  sconn->callback_context = context;
  silc_schedule_task_add(server->schedule, 0, 
			 silc_server_backup_connect_to_router,
			 sconn, 2, 0, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

SILC_TASK_CALLBACK(silc_server_backup_connected_later)
{
  SilcServerBackupProtocolContext proto_ctx = 
    (SilcServerBackupProtocolContext)context;
  SilcServer server = proto_ctx->server;
  SilcSocketConnection sock = proto_ctx->sock;

  SILC_LOG_DEBUG(("Starting backup resuming protocol as initiator"));

  /* Run the backup resuming protocol */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_BACKUP,
		      &sock->protocol, proto_ctx, 
		      silc_server_protocol_backup_done);
  silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
}

/* Called when we've established connection back to our primary router
   when we've acting as backup router and have replaced the primary router
   in the cell. This function will start the backup resuming protocol. */

void silc_server_backup_connected(SilcServer server,
				  SilcServerEntry server_entry,
				  void *context)
{
  SilcServerBackupProtocolContext proto_ctx;
  SilcSocketConnection sock = (SilcSocketConnection)server_entry->connection;

  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = server;
  proto_ctx->sock = sock;
  proto_ctx->responder = FALSE;
  proto_ctx->type = SILC_SERVER_BACKUP_START;
  proto_ctx->start = time(0);

  /* Start through scheduler */
  silc_schedule_task_add(server->schedule, 0,
			 silc_server_backup_connected_later,
			 proto_ctx, 0, 1,
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Called when normal server has connected to its primary router after
   backup router has sent the START packet in reusming protocol. We will
   move the protocol context from the backup router connection to the
   primary router. */

static void silc_server_backup_connect_primary(SilcServer server,
					       SilcServerEntry server_entry,
					       void *context)
{
  SilcSocketConnection backup_router = (SilcSocketConnection)context;
  SilcSocketConnection sock = (SilcSocketConnection)server_entry->connection;
  SilcIDListData idata = (SilcIDListData)server_entry;
  SilcServerBackupProtocolContext ctx = 
    (SilcServerBackupProtocolContext)backup_router->protocol->context;
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("********************************"));
  SILC_LOG_DEBUG(("Sending CONNECTED packet, session %d", ctx->session));

  /* Send the CONNECTED packet back to the backup router. */
  buffer = silc_buffer_alloc(2);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_CHAR(SILC_SERVER_BACKUP_CONNECTED),
		     SILC_STR_UI_CHAR(ctx->session),
		     SILC_STR_END);
  silc_server_packet_send(server, backup_router, 
			  SILC_PACKET_RESUME_ROUTER, 0, 
			  buffer->data, buffer->len, FALSE);
  silc_buffer_free(buffer);

  /* The primary connection is disabled until it sends the RESUMED packet
     to us. */
  idata->status |= SILC_IDLIST_STATUS_DISABLED;

  /* Move this protocol context from this backup router connection to
     the primary router connection since it will send the subsequent
     packets in this protocol. We don't talk with backup router 
     anymore. */
  sock->protocol = backup_router->protocol;
  ctx->sock = (SilcSocketConnection)server_entry->connection;
  backup_router->protocol = NULL;
}

/* Resume protocol with RESUME_ROUTER packet: 

   SILC_PACKET_RESUME_ROUTER:

   <uint8 type> <uint8 Session ID>

   <type>          = the protocol opcode
   <Session ID>    = Identifier for this packet and any subsequent reply
                     packets must include this identifier.

   Types:

     1    = To router: Comensing backup resuming protocol. This will
            indicate that the sender is backup router acting as primary
            and the receiver is primary router that has been replaced by
	    the backup router.

	    To server. Comensing backup resuming protocol. This will
	    indicate that the sender is backup router and the receiver
	    must reconnect to the real primary router of the cell.

     2    = To Router: Comesning backup resuming protocol in another
            cell.  The receiver will connect to its primary router 
	    (the router that is now online again) but will not use
	    the link.  If the receiver is not configured to connect
	    to any router it does as locally configured.  The sender
	    is always backup router.

	    To server: this is never sent to server.

     3    = To backup router: Sender is normal server or router and it
            tells to backup router that they have connected to the
	    primary router.  Backup router never sends this type.

     4    = To router: Ending backup resuming protocol. This is sent
            to the real primary router to tell that it can take over
	    the task as being primary router.

	    To server: same as sending for router.

	    Backup router sends this also to the primary route but only
	    after it has sent them to normal servers and has purged all
	    traffic coming from normal servers.

     5    = To router: Sender is the real primary router after it has
            received type 4 from backup router. To tell that it is again
	    primary router of the cell.

     20   = To router: This is sent only when router is connecting to
            another router and has been replaced by an backup router.
	    The sender knows that the connectee has been replaced.

 */

/* Backup resuming protocol. This protocol is executed when the primary
   router wants to resume its position as being primary router. */

SILC_TASK_CALLBACK_GLOBAL(silc_server_protocol_backup)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerBackupProtocolContext ctx = protocol->context;
  SilcServer server = ctx->server;
  SilcBuffer packet;
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;
  SilcServerEntry server_entry;
  int i;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_UNKNOWN)
    protocol->state = SILC_PROTOCOL_STATE_START;

  SILC_LOG_DEBUG(("State=%d", protocol->state));

  switch(protocol->state) {
  case SILC_PROTOCOL_STATE_START:
    if (ctx->responder == FALSE) {
      /* Initiator of the protocol. We are backup router */

      packet = silc_buffer_alloc(2);
      silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));

      SILC_LOG_DEBUG(("********************************"));
      SILC_LOG_DEBUG(("Sending START packets"));

      /* Send the START packet to primary router and normal servers. */
      if (silc_idcache_get_all(server->local_list->servers, &list)) {
	if (silc_idcache_list_first(list, &id_cache)) {
	  while (id_cache) {
	    server_entry = (SilcServerEntry)id_cache->context;
	    if ((server_entry == server->id_entry) || 
		!server_entry->connection) {
	      if (!silc_idcache_list_next(list, &id_cache))
		break;
	      else
		continue;
	    }

	    ctx->sessions = silc_realloc(ctx->sessions,
					 sizeof(*ctx->sessions) *
					 (ctx->sessions_count + 1));
	    ctx->sessions[ctx->sessions_count].session = ctx->sessions_count;
	    ctx->sessions[ctx->sessions_count].connected = FALSE;
	    ctx->sessions[ctx->sessions_count].server_entry = server_entry;

	    SILC_LOG_DEBUG(("********************************"));
	    SILC_LOG_DEBUG(("START for session %d", ctx->sessions_count));

	    /* This connection is performing this protocol too now */
	    ((SilcSocketConnection)server_entry->connection)->protocol =
	      protocol;

	    if (server_entry->server_type == SILC_ROUTER)
	      packet->data[0] = SILC_SERVER_BACKUP_START;
	    else
	      packet->data[0] = SILC_SERVER_BACKUP_START_GLOBAL;
	    packet->data[1] = ctx->sessions_count;
	    silc_server_packet_send(server, server_entry->connection,
				    SILC_PACKET_RESUME_ROUTER, 0, 
				    packet->data, packet->len, FALSE);
	    ctx->sessions_count++;

	    if (!silc_idcache_list_next(list, &id_cache))
	      break;
	  }
	}

	silc_idcache_list_free(list);
      }

      silc_buffer_free(packet);

      /* If we are router then announce our possible servers. */
      if (server->server_type == SILC_ROUTER)
	silc_server_announce_servers(server, FALSE, 0, ctx->sock);
      silc_server_announce_clients(server, 0, ctx->sock);
      silc_server_announce_channels(server, 0, ctx->sock);

      protocol->state++;
    } else {
      /* Responder of the protocol. */
      SilcServerConfigSectionServerConnection *primary;

      /* We should have received START or START_GLOBAL packet */
      if (ctx->type != SILC_SERVER_BACKUP_START &&
	  ctx->type != SILC_SERVER_BACKUP_START_GLOBAL) {
	SILC_LOG_DEBUG(("Bad resume router packet"));
	break;
      }

      SILC_LOG_DEBUG(("********************************"));
      SILC_LOG_DEBUG(("Received START packet, reconnecting to router"));

      /* Connect to the primary router that was down that is now supposed
	 to be back online. We send the CONNECTED packet after we've
	 established the connection to the primary router. */
      primary = silc_server_config_get_primary_router(server->config);
      if (primary) {
	silc_server_backup_reconnect(server,
				     primary->host, primary->port,
				     silc_server_backup_connect_primary,
				     ctx->sock);
	if (server->server_type == SILC_ROUTER &&
	    (!server->router || 
	     server->router->data.status & SILC_IDLIST_STATUS_DISABLED))
	  protocol->state++;
	else
	  protocol->state = SILC_PROTOCOL_STATE_END;

      } else {
	/* Nowhere to connect just return the CONNECTED packet */

	SILC_LOG_DEBUG(("********************************"));
	SILC_LOG_DEBUG(("Sending CONNECTED packet, session %d", ctx->session));
	
	/* Send the CONNECTED packet back to the backup router. */
	packet = silc_buffer_alloc(2);
	silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
	silc_buffer_format(packet,
			   SILC_STR_UI_CHAR(SILC_SERVER_BACKUP_CONNECTED),
			   SILC_STR_UI_CHAR(ctx->session),
			   SILC_STR_END);
	silc_server_packet_send(server, ctx->sock, 
				SILC_PACKET_RESUME_ROUTER, 0, 
				packet->data, packet->len, FALSE);
	silc_buffer_free(packet);
	protocol->state++;
      }

      ctx->sessions = silc_realloc(ctx->sessions,
				   sizeof(*ctx->sessions) *
				   (ctx->sessions_count + 1));
      ctx->sessions[ctx->sessions_count].session = ctx->session;
      ctx->sessions_count++;
    }
    break;

  case 2:
    if (ctx->responder == FALSE) {
      /* Initiator */

      /* We should have received CONNECTED packet */
      if (ctx->type != SILC_SERVER_BACKUP_CONNECTED) {
	SILC_LOG_DEBUG(("Bad resume router packet"));
	break;
      }

      SILC_LOG_DEBUG(("********************************"));
      SILC_LOG_DEBUG(("Received CONNECTED packet, session %d", ctx->session));

      for (i = 0; i < ctx->sessions_count; i++) {
	if (ctx->sessions[i].session == ctx->session) {
	  ctx->sessions[i].connected = TRUE;
	  break;
	}
      }

      for (i = 0; i < ctx->sessions_count; i++) {
	if (!ctx->sessions[i].connected)
	  return;
      }

      SILC_LOG_DEBUG(("********************************"));
      SILC_LOG_DEBUG(("Sending ENDING packet to primary"));

      for (i = 0; i < ctx->sessions_count; i++)
	if (ctx->sessions[i].server_entry == ctx->sock->user_data)
	  ctx->session = ctx->sessions[i].session;

      /* We've received all the CONNECTED packets and now we'll send the
	 ENDING packet to the new primary router. */
      packet = silc_buffer_alloc(2);
      silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
      silc_buffer_format(packet,
			 SILC_STR_UI_CHAR(SILC_SERVER_BACKUP_ENDING),
			 SILC_STR_UI_CHAR(ctx->session),
			 SILC_STR_END);
      silc_server_packet_send(server, ctx->sock, 
			      SILC_PACKET_RESUME_ROUTER, 0, 
			      packet->data, packet->len, FALSE);
      silc_buffer_free(packet);

      protocol->state = SILC_PROTOCOL_STATE_END;
    } else {
      /* Responder */

      /* We should have been received ENDING packet */
      if (ctx->type != SILC_SERVER_BACKUP_ENDING) {
	SILC_LOG_DEBUG(("Bad resume router packet"));
	break;
      }

      SILC_LOG_DEBUG(("********************************"));
      SILC_LOG_DEBUG(("Received ENDING packet, sending RESUMED packets"));

      /* This state is received by the primary router but also servers
	 and perhaps other routers so check that if we are the primary
	 router of the cell then start sending RESUMED packets.  If we
	 are normal server or one of those other routers then procede
	 to next state. */
      if (server->router &&
	  !(server->router->data.status & SILC_IDLIST_STATUS_DISABLED) &&
	  silc_server_config_is_primary_route(server->config)) {
	/* We'll wait for RESUMED packet */
	protocol->state = SILC_PROTOCOL_STATE_END;
	break;
      }

      /* Switch announced informations to our entry instead of using the
	 backup router. */
      silc_server_update_clients_by_server(server, ctx->sock->user_data,
					   server->id_entry, TRUE, FALSE);

      packet = silc_buffer_alloc(2);
      silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));

      /* We are the primary router, start sending RESUMED packets. */
      if (silc_idcache_get_all(server->local_list->servers, &list)) {
	if (silc_idcache_list_first(list, &id_cache)) {
	  while (id_cache) {
	    server_entry = (SilcServerEntry)id_cache->context;
	    if ((server_entry == server->id_entry) || 
		!server_entry->connection) {
	      if (!silc_idcache_list_next(list, &id_cache))
		break;
	      else
		continue;
	    }

	    SILC_LOG_DEBUG(("********************************"));
	    SILC_LOG_DEBUG(("RESUMED packet"));

	    /* This connection is performing this protocol too now */
	    ((SilcSocketConnection)server_entry->connection)->protocol =
	      protocol;

	    if (server_entry->server_type == SILC_ROUTER)
	      packet->data[0] = SILC_SERVER_BACKUP_RESUMED;
	    else
	      packet->data[0] = SILC_SERVER_BACKUP_RESUMED_GLOBAL;
	    silc_server_packet_send(server, server_entry->connection,
				    SILC_PACKET_RESUME_ROUTER, 0, 
				    packet->data, packet->len, FALSE);

	    if (!silc_idcache_list_next(list, &id_cache))
	      break;
	  }
	}

	silc_idcache_list_free(list);
      }

      silc_buffer_free(packet);

      /* For us this is the end of this protocol. */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, server->schedule);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_END:
    {
      SilcIDListData idata;
      SilcServerEntry primary;
      SilcServerEntry backup_router;

      /* We should have been received RESUMED packet from our primary
	 router. */
      if (ctx->type != SILC_SERVER_BACKUP_RESUMED &&
	  ctx->type != SILC_SERVER_BACKUP_RESUMED_GLOBAL) {
	SILC_LOG_DEBUG(("Bad resume router packet"));
	break;
      }

      SILC_LOG_DEBUG(("********************************"));
      SILC_LOG_DEBUG(("Received RESUMED packet"));

      /* We have now new primary router. All traffic goes there from now on. */
      if (server->backup_router)
	server->server_type = SILC_BACKUP_ROUTER;

      primary = (SilcServerEntry)ctx->sock->user_data;
      if (silc_server_backup_replaced_get(server, primary->id, 
					  &backup_router)) {

	if (backup_router == server->router) {
	  server->id_entry->router = ctx->sock->user_data;
	  server->router = ctx->sock->user_data;
	  SILC_LOG_INFO(("Switching back to primary router %s",
			 server->router->server_name));
	  SILC_LOG_DEBUG(("********************************"));
	  SILC_LOG_DEBUG(("Switching back to primary router %s",
			  server->router->server_name));
	  idata = (SilcIDListData)server->router;
	  idata->status &= ~SILC_IDLIST_STATUS_DISABLED;

	  /* Update the client entries of the backup router to the new 
	     primary router. */
	  silc_server_update_clients_by_server(server, backup_router,
					       primary, TRUE, FALSE);
	  silc_server_backup_replaced_del(server, backup_router);
	  silc_server_backup_add(server, backup_router,
				 backup_router->server_type != SILC_ROUTER ?
				 TRUE : FALSE);
	}

	/* Announce all of our information to the new primary router. */
	if (server->server_type == SILC_ROUTER)
	  silc_server_announce_servers(server, FALSE, 0,
				       server->router->connection);
	
	/* Announce our clients and channels to the router */
	silc_server_announce_clients(server, 0,
				     server->router->connection);
	silc_server_announce_channels(server, 0,
				      server->router->connection);
      }

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, server->schedule);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    /* Protocol has ended, call the final callback */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_FAILURE:
    /* Protocol has ended, call the final callback */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_UNKNOWN:
    break;
  }
}

SILC_TASK_CALLBACK(silc_server_protocol_backup_done)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerBackupProtocolContext ctx = protocol->context;
  SilcServer server = ctx->server;
  SilcServerEntry server_entry;
  SilcSocketConnection sock;
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    SILC_LOG_ERROR(("Error occurred during backup router resuming protcool"));
  }

  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	server_entry = (SilcServerEntry)id_cache->context;
	sock = (SilcSocketConnection)server_entry->connection;

	if (sock->protocol && sock->protocol->protocol &&
	    sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_BACKUP)
	  sock->protocol = NULL;
	
	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  if (ctx->sock->protocol)
    ctx->sock->protocol = NULL;
  silc_protocol_free(protocol);
  silc_free(ctx->sessions);
  silc_free(ctx);
}