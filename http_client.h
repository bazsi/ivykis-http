// @@@ REWRITE THIS

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

#ifndef __IV_HTTP_CLIENT_H
#define __IV_HTTP_CLIENT_H

#include <iv.h>
#include <netinet/in.h>

struct http_client_request
{
	char			*method;
	char			*hostname;
	int			port;
	char			*url;
	char			*params;	// @@@ list_head
	char			*headers;	// @@@ list_head
	int			entity_length;
	char			*entity_body;
	void			*cookie;
	void			(*handler)(void *);

	int			state;
	// @@@ dns query context
	int			hostname_lookup_callback_scheduled;
	struct iv_task		hostname_lookup;
	// @@@ temp hack until we get async DNS
	char			*redirect_hostname;
	int			redirect_port;
	char			*redirect_url;
	struct in_addr		resolved_ip;
	char			*redirect;
	char			*redirect_last;
	int			recursion_limit;
	int			response_code;
	struct iv_fd		fd;
	int			entity_ptr;
	int			read_ptr;
	int			parse_ptr;
	char			rcvbuf[4096];
};

void http_client_request_start(struct http_client_request *req);
void http_client_request_cancel(struct http_client_request *req);
int http_client_request_get_fd(struct http_client_request *req);
int http_client_request_get_resp_code(struct http_client_request *req);


#endif
