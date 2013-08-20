#define _GNU_SOURCE

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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <syslog.h>
#include <unistd.h>
#include "http_client.h"

/* @@@TODO:
   per-ip connection limiting (mutex)
   what data to init where?
   chunked encoding, pipelining, keepalive
*/


static void start_hostname_lookup(struct http_client_request *);


static void abort_me(struct http_client_request *req, int close_fd,
		     int callback)
{
	// @@@ cancel hostname lookup
	if (req->hostname_lookup_callback_scheduled)
		iv_task_unregister(&req->hostname_lookup);

	free(req->redirect);
	free(req->redirect_last);

	if (req->fd.fd != -1) {
		iv_fd_unregister(&req->fd);
		if (close_fd) {
			close(req->fd.fd);
			req->fd.fd = -1;
		}
	}

	if (callback)
		req->handler(req->cookie);
}

static void parse_first_line(struct http_client_request *req, char *line)
{
	char *code;

	code = strchr(line, ' ');
	if (code == NULL || code[0] == 0) {
		req->state = EINVAL;
		return;
	}

	if (sscanf(code + 1, "%d", &req->response_code) != 1) {
		req->state = EINVAL;
		return;
	}
}

static void parse_header_line(struct http_client_request *req, char *line)
{
	if (line[0] == 0) {
		req->state = 0;
		return;
	}

	if (!strncmp(line, "Location: ", 10)) {
		char *r = strdup(line + 10);
		if (r != NULL) {
			free(req->redirect);
			req->redirect = r;
		}
		return;
	}
}

static int commit(struct http_client_request *req, int bytes)
{
	char buf[1024];

	while (bytes) {
		int toread;
		int ret;

		toread = bytes;
		if (toread > sizeof(buf))
			toread = sizeof(buf);

		ret = read(req->fd.fd, buf, toread);
		if (ret < 0)
			return -1;

		bytes -= ret;
	}

	return 0;
}

static void process_data(struct http_client_request *req)
{
	int bytes_to_commit = 0;

	while (req->state == EINPROGRESS) {
		char *parse_head = req->rcvbuf + req->parse_ptr;
		char *endline;
		int bytes_left;
		int line_size;

		bytes_left = req->read_ptr - req->parse_ptr;

		endline = memchr(parse_head, '\n', bytes_left);
		if (endline == NULL) {
			endline = memchr(parse_head, '\r', bytes_left);
			if (endline == NULL) {
				bytes_to_commit += bytes_left;
				break;
			}
		}

		line_size = endline - parse_head + 1;
		bytes_to_commit += line_size;
		req->parse_ptr += line_size;

		*endline = 0;
		if (parse_head != endline && endline[-1] == '\r')
			endline[-1] = 0;

		if (req->response_code == -1)
			parse_first_line(req, parse_head);
		else
			parse_header_line(req, parse_head);
	}

	commit(req, bytes_to_commit);
}

static int split_url(char *uri, char **host, int *port, char **url)
{
	char *_host;
	char *_port;
	char *_url;
	int len;

	if (strncmp(uri, "http://", 7))
		return -1;

	_host = uri + 7;
	_port = strchr(_host, ':');
	_url = strchr(_host, '/');

	if (_url == NULL)
		return -1;

	if (_port != NULL && _port - _url > 0)
		_port = NULL;

	*port = 80;
	if (_port != NULL && sscanf(_port+1, "%d", port) != 1)
		return -1;

	len = _port ? _port - _host : _url - _host;
	memmove(uri, _host, len);
	uri[len] = 0;
	*host = uri;

	// @@@ check if url has ?-style parameters
	*url = _url;

	return 0;
}

static void got_data(void *_req)
{
	struct http_client_request *req = (struct http_client_request *)_req;
	int bytes_left;
	char *ptr;
	int size;

	ptr = req->rcvbuf + req->read_ptr;
	size = sizeof(req->rcvbuf) - req->read_ptr;

	bytes_left = recv(req->fd.fd, ptr, size, MSG_PEEK);
	if (bytes_left == 0) {
		req->state = ECONNABORTED;
		abort_me(req, 1, 1);
		return;
	}

	if (bytes_left < 0) {
		if (errno != EAGAIN) {
			req->state = errno;
			abort_me(req, 1, 1);
		}
		return;
	}

	req->read_ptr += bytes_left;
	process_data(req);

	if (req->state == EINPROGRESS)
		return;

	// @@@ check http status code too?
	if (req->state == 0 && req->redirect != NULL) {
		char *host;
		int port;
		char *url;

		if (!req->recursion_limit--) {
			req->state = ELOOP;
			abort_me(req, 1, 1);
			return;
		}

		if (split_url(req->redirect, &host, &port, &url) < 0) {
			req->state = EINVAL;
			abort_me(req, 1, 1);
			return;
		}

		req->redirect_hostname = host;
		req->redirect_port = port;
		req->redirect_url = url;

		free(req->redirect_last);
		req->redirect_last = req->redirect;
		req->redirect = NULL;

		iv_fd_unregister(&req->fd);
		close(req->fd.fd);
		req->fd.fd = -1;
		req->state = EINPROGRESS;
		start_hostname_lookup(req);

		return;
	}

	abort_me(req, !!req->state, 1);
}

static void got_output_space(void *_req)
{
	struct http_client_request *req = (struct http_client_request *)_req;
	int bytes_left;
	int ret;

	bytes_left = req->entity_length - req->entity_ptr;
	if (bytes_left == 0)
		abort();

	ret = write(req->fd.fd, req->entity_body + req->entity_ptr,
			bytes_left);
	if (ret < 0) {
		if (errno != EAGAIN) {
			req->state = errno;
			abort_me(req, 1, 1);
		}
		return;
	}

	req->entity_ptr += ret;
	if (req->entity_ptr == req->entity_length)
		iv_fd_set_handler_out(&req->fd, NULL);
}

static void connect_successful(struct http_client_request *req)
{
	struct iovec iov[9];
	int ret;

	req->response_code = -1;
	req->entity_ptr = 0;
	req->read_ptr = 0;
	req->parse_ptr = 0;

	iov[0].iov_base = req->method;
	iov[0].iov_len = strlen(req->method);
	iov[1].iov_base = " ";
	iov[1].iov_len = 1;
	iov[2].iov_base = req->redirect_url;
	iov[2].iov_len = strlen(req->redirect_url);
	iov[3].iov_base = req->params;
	iov[3].iov_len = strlen(req->params);
	iov[4].iov_base = " HTTP/1.0\r\nHost: ";
	iov[4].iov_len = 17;
	iov[5].iov_base = req->redirect_hostname;
	iov[5].iov_len = strlen(req->redirect_hostname);
	iov[6].iov_base = "\r\nUser-Agent: http_client"
			  "\r\nConnection: close\r\n";
	iov[6].iov_len = 46;
	iov[7].iov_base = req->headers;
	iov[7].iov_len = strlen(req->headers);
	iov[8].iov_base = "\r\n";
	iov[8].iov_len = 2;

	ret = writev(req->fd.fd, iov, 9);
	if (ret != iov[0].iov_len + iov[1].iov_len + iov[2].iov_len +
		   iov[3].iov_len + iov[4].iov_len + iov[5].iov_len +
		   iov[6].iov_len + iov[7].iov_len + iov[8].iov_len) {
		req->state = ret < 0 ? errno : EINVAL;
		abort_me(req, 1, 1);
		return;
	}

	iv_fd_set_handler_in(&req->fd, got_data);
	if (req->entity_length && req->entity_body != NULL)
		iv_fd_set_handler_out(&req->fd, got_output_space);
	else
		iv_fd_set_handler_out(&req->fd, NULL);
}

static void connect_done(void *_req)
{
	struct http_client_request *req = (struct http_client_request *)_req;
	socklen_t retlen;
	int ret;

	retlen = sizeof(ret);
	if (getsockopt(req->fd.fd, SOL_SOCKET, SO_ERROR, &ret, &retlen) < 0) {
		req->state = errno;
		abort_me(req, 1, 1);
		return;
	}

	if (ret) {
		if (ret != EINPROGRESS) {
			req->state = ret;
			abort_me(req, 1, 1);
		}
		return;
	}

	connect_successful(req);
}

static void hostname_lookup_done(void *_req)
{
	struct http_client_request *req = (struct http_client_request *)_req;
	struct sockaddr_in addr;
	int ret;
	int fd;

	req->hostname_lookup_callback_scheduled = 0;

	if (req->resolved_ip.s_addr == htonl(0xffffffff)) {
		req->state = ENOENT;
		abort_me(req, 1, 1);
		return;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		req->state = errno;
		abort_me(req, 0, 1);
		return;
	}

	req->fd.fd = fd;
	req->fd.cookie = (void *)req;
	req->fd.handler_in = connect_done;
	req->fd.handler_out = connect_done;
	iv_fd_register(&req->fd);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(req->redirect_port);
	addr.sin_addr = req->resolved_ip;

	ret = connect(req->fd.fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == 0) {
		connect_successful(req);
		return;
	}

	if (errno != EINPROGRESS) {
		req->state = errno;
		abort_me(req, 1, 1);
	}
}

static void start_hostname_lookup(struct http_client_request *req)
{
	// @@@ start lookup for req->redirect_hostname
	if (!inet_aton(req->redirect_hostname, &req->resolved_ip))
		req->resolved_ip.s_addr = htonl(0xffffffff);

	req->hostname_lookup_callback_scheduled = 1;
	iv_task_register(&req->hostname_lookup);
}

void http_client_request_start(struct http_client_request *req)
{
	req->state = EINPROGRESS;

	req->hostname_lookup_callback_scheduled = 0;
	IV_TASK_INIT(&req->hostname_lookup);
	req->hostname_lookup.cookie = (void *)req;
	req->hostname_lookup.handler = hostname_lookup_done;

	req->redirect = NULL;
	req->redirect_last = NULL;
	req->redirect_hostname = req->hostname;
	req->redirect_port = req->port;
	req->redirect_url = req->url;
	req->recursion_limit = 10;

	IV_FD_INIT(&req->fd);
	req->fd.fd = -1;

	start_hostname_lookup(req);
}

void http_client_request_cancel(struct http_client_request *req)
{
	if (req->state == EINPROGRESS) {
		abort_me(req, 1, 0);
		req->state = ECANCELED;
	}
}

int http_client_request_get_fd(struct http_client_request *req)
{
	return req->state ? -req->state : req->fd.fd;
}

int http_client_request_get_resp_code(struct http_client_request *req)
{
	return req->response_code;
}
