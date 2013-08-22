/*
 * ivykis, an event handling library
 * Copyright (C) 2002, 2003 Lennert Buytenhek
 * Dedicated to Marija Kulikova.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __IV_HTTP_SERVER_H
#define __IV_HTTP_SERVER_H

#include <iv.h>
#include <iv_list.h>

struct http_request;
struct http_request_interest;

int http_register_interest(struct http_request_interest *);
void http_unregister_interest(struct http_request_interest *);
int http_dequeue_request(struct http_request_interest *,
			 struct http_request **);

char *http_request_get_uri_param(struct http_request *, char *);
char *http_request_get_header_param(struct http_request *, char *);
int http_request_get_peername(struct http_request *, struct sockaddr *,
			      socklen_t *);
void http_request_set_status_code(struct http_request *, int);
void http_request_set_content_length(struct http_request *, int);
void http_request_set_content_type(struct http_request *, char *);
void http_request_set_server(struct http_request *, char *);

int http_request_start_reply(struct http_request *);
int http_request_write(struct http_request *, char *, size_t);
int http_request_end_reply(struct http_request *);

int http_request_steal_socket(struct http_request *, int);
void http_request_finish_request(struct http_request *);


/* internals *****************************************************************/
struct http_tuple
{
	char					*key;
	char					*value;
	struct iv_list_head			list;
};

struct http_request_interest
{
	char 					*ip;
	char					*port;
	char					*method;
	char					*host;
	char					*uri;

	void					*cookie;
	void					(*handler)(void *);

	struct iv_list_head			list;
	struct http_listening_socket		*sock;
	struct iv_list_head			reqs;
};


#define IV_HTTP_REPLY_CONTENT_LENGTH		0
#define IV_HTTP_REPLY_CHUNKED			1
#define IV_HTTP_REPLY_CONNECTION_CLOSE		2

#define MAXREQBUF				4096

#define IV_HTTP_VERSION_0_9			9
#define IV_HTTP_VERSION_1_0			10
#define IV_HTTP_VERSION_1_1			11

struct http_request
{
	/* Parsed fields.  */
	char					*method;
	char					*uri;
	struct iv_list_head			uri_params;
	char					*_version;
	struct iv_list_head			header_params;

	/* Determined fields.  */
	char					*host;
	int					reply_mode;
	int					http_version;
	int					connection_close;
	int					accept_chunked;

	/* Reply fields.  */
	int					status_code;
	int					content_length;
	int					content_sent;
	char					*content_type;
	char					*server;

	/* Internal state.  */
	struct iv_list_head			list;
	struct http_connection			*conn;
	char					inbuf[MAXREQBUF];
	int					parse_ptr;
	int					read_ptr;
	int					end_ptr;
	int					done;
};


#endif
