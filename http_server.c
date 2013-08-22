#define _GNU_SOURCE

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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include "http_server.h"

static int max_requests_per_connection = 100;


/**********************/
struct http_listening_socket
{
	struct iv_list_head			list;

	u_int32_t				ip;
	u_int16_t				port;
	struct iv_fd				fd;

	struct iv_list_head			interests;
	struct iv_list_head			connections;
};

struct http_connection
{
	struct iv_list_head			list;
	struct http_listening_socket		*sock;
	struct iv_fd				fd;
	struct sockaddr_in			peername;
	socklen_t				peername_length;
	struct iv_timer				timeout;
	struct http_request			*current;
	int					handling_request;
	int					max_requests;
};

static void http_get_connection(void *);
static void http_kill_connection(struct http_connection *);
static void http_connection_get_data(void *);
static void http_fail_request(struct http_request *);



/**********************/
static char *__spn(char *s, char *accept)
{
	return s + strspn(s, accept);
}

static char *__cspn(char *s, char *reject)
{
	return s + strcspn(s, reject);
}

static int set_reset_mode(int fd, int mode)
{
	struct linger l;

	l.l_onoff = mode;
	l.l_linger = 0;
	return setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
}

static int create_socket(u_int32_t ip, u_int16_t port)
{
	struct sockaddr_in addr;
	int fd;
	int yes;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		close(fd);
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	if (listen(fd, 6) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}


static struct iv_list_head sockets = IV_LIST_HEAD_INIT(sockets);

static struct http_listening_socket *
create_http_socket(u_int32_t ip, u_int16_t port)
{
	struct http_listening_socket *s;

	s = malloc(sizeof(struct http_listening_socket));
	if (s != NULL) {
		int fd;

		fd = create_socket(ip, port);
		if (fd < 0) {
			free(s);
			return NULL;
		}

		INIT_IV_LIST_HEAD(&(s->list));
		s->ip = ip;
		s->port = port;

		IV_FD_INIT(&(s->fd));
		s->fd.fd = fd;
		s->fd.cookie = (void *)s;
		s->fd.handler_in = http_get_connection;
		iv_fd_register(&(s->fd));

		INIT_IV_LIST_HEAD(&(s->interests));
		INIT_IV_LIST_HEAD(&(s->connections));

		iv_list_add_tail(&(s->list), &sockets);
	}

	return s;
}

static struct http_listening_socket *
find_http_socket(u_int32_t ip, u_int16_t port)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, &sockets) {
		struct http_listening_socket *s;

		s = iv_list_entry(lh, struct http_listening_socket, list);
		if (s->ip == ip && s->port == port)
			return s;
	}

	return create_http_socket(ip, port);
}

static void destroy_http_socket(struct http_listening_socket *s)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	if (!iv_list_empty(&(s->interests))) {
		syslog(LOG_CRIT, "destroy_http_socket with active interests");
		abort();
	}

	iv_fd_unregister(&(s->fd));
	close(s->fd.fd);

	iv_list_for_each_safe (lh, lh2, &(s->connections)) {
		struct http_connection *conn;

		conn = iv_list_entry(lh, struct http_connection, list);

		if (conn->handling_request) {
			iv_list_del_init(&conn->list);
			conn->sock = NULL;
			conn->current->connection_close = 1;
		}
		else {
			http_kill_connection(conn);
		}

	}

	free(s);
}


/**********************/
static void http_kill_request(struct http_request *req)
{
	if (req->conn && req->conn->current == req)
		req->conn->current = NULL;

	if (req->content_type)
		free(req->content_type);
	if (req->server)
		free(req->server);
	free(req);
}

static void __http_kill_connection(struct http_connection *conn, int cl)
{
	if (conn->current)
		http_kill_request(conn->current);
	iv_fd_unregister(&(conn->fd));
	if (cl) {
		if (conn->handling_request)
			shutdown(conn->fd.fd, SHUT_WR);
		close(conn->fd.fd);
	}

	iv_list_del(&(conn->list));
	free(conn);
}

static void http_kill_connection(struct http_connection *conn)
{
	if (!conn->handling_request)
		iv_timer_unregister(&(conn->timeout));
	__http_kill_connection(conn, 1);
}

static void http_connection_timeout(void *_conn)
{
	struct http_connection *conn = (struct http_connection *)_conn;
	__http_kill_connection(conn, 1);
}

static void http_connection_start_expecting_requests(struct http_connection *conn)
{
	iv_fd_set_handler_in(&conn->fd, http_connection_get_data);

	/* set up request timeout */
	iv_validate_now();
	conn->timeout.expires = iv_now;
	conn->timeout.expires.tv_sec += 10;
	iv_timer_register(&(conn->timeout));
}

static void http_connection_stop_expecting_requests(struct http_connection *conn)
{
	iv_fd_set_handler_in(&conn->fd, NULL);
	iv_timer_unregister(&conn->timeout);
}

static void http_get_connection(void *_sock)
{
	struct http_listening_socket *s = (struct http_listening_socket *)_sock;
	struct sockaddr_in addr;
	socklen_t addrlen;
	int fd;

	addrlen = sizeof(addr);
	fd = accept(s->fd.fd, (struct sockaddr *)&addr, &addrlen);
	if (fd >= 0) {
		struct http_connection *conn;

		conn = malloc(sizeof(struct http_connection));
		if (conn == NULL) {
			close(fd);
			return;
		}

		set_reset_mode(fd, 1);

		conn->peername = addr;
		conn->peername_length = addrlen;

		INIT_IV_LIST_HEAD(&(conn->list));
		conn->handling_request = 0;
		conn->sock = s;
		conn->current = NULL;

		IV_FD_INIT(&(conn->fd));
		conn->fd.fd = fd;
		conn->fd.cookie = (void *)conn;
		iv_fd_register(&(conn->fd));

		IV_TIMER_INIT(&(conn->timeout));
		conn->timeout.handler = http_connection_timeout;
		conn->timeout.cookie = (void *)conn;

		conn->max_requests = max_requests_per_connection;
		iv_list_add_tail(&(conn->list), &(s->connections));

		http_connection_start_expecting_requests(conn);

		return;
	}

	// @@@ check errno, ECONNABORTED is okay
}



/**********************/
static struct http_request_interest *
find_best_client(struct http_listening_socket *sock, struct http_request *req)
{
	struct http_request_interest *best;
	int bestscore;
	struct iv_list_head *lh;

	if (sock == NULL)
		return NULL;

	best = NULL;
	bestscore = -1;

	iv_list_for_each (lh, &(sock->interests)) {
		struct http_request_interest *i;
		int score;

		i = iv_list_entry(lh, struct http_request_interest, list);
		score = 0;

		if (i->method != NULL) {
			if (strcmp(i->method, req->method))
				continue;
			score++;
		}

		if (i->host != NULL) {
			if (strcmp(i->host, req->host))
				continue;
			score++;
		}

		if (i->uri != NULL) {
			int len;

			len = strlen(i->uri);
			if (strncmp(i->uri, req->uri, len))
				continue;
			score += 10 * len;
		}

		if (score > bestscore) {
			best = i;
			bestscore = score;
		}
	}

	return best;
}

static void http_attach_new_request(struct http_connection *conn)
{
	struct http_request *req;

	// @@@ review init stuff

	req = malloc(sizeof(struct http_request));
	if (req != NULL) {
		req->method = NULL;
		req->host = NULL;
		req->uri = NULL;
		INIT_IV_LIST_HEAD(&(req->uri_params));
		req->_version = NULL;
		INIT_IV_LIST_HEAD(&(req->header_params));
		req->status_code = 200;
		req->http_version = -1;
		req->content_length = -1;
		req->content_sent = 0;
		req->content_type = NULL;
		req->server = NULL;
		req->reply_mode = -1;
		INIT_IV_LIST_HEAD(&(req->list));
		req->conn = conn;
		req->parse_ptr = 0;
		req->read_ptr = 0;
		req->end_ptr = sizeof(req->inbuf);
		req->done = 0;

		conn->current = req;
	}
}

static struct http_tuple *http_alloc_tuple(struct http_request *req)
{
	struct http_tuple *tup;

	tup = NULL;
	if (req->read_ptr + sizeof(struct http_tuple) < req->end_ptr) {
		req->end_ptr -= sizeof(struct http_tuple);
		tup = (struct http_tuple *)(req->inbuf + req->end_ptr);
		INIT_IV_LIST_HEAD(&(tup->list));
	}

	return tup;
}

static int to_hex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	return -1;
}

static void hexhex_sanitise(char *line)
{
	char *rptr;
	char *wptr;
	int hexhex;
	int hexval;
	int utf8;
	unsigned int utfval;

	rptr = line;
	wptr = line;
	hexhex = 0;
	hexval = 0;		// shut gcc up
	utf8 = 0;
	utfval = 0;		// shut gcc up

	while (*rptr) {
		unsigned char c = *rptr++;
		int temp;

		switch (hexhex) {
		case 0:
			if (c == '%') {
				hexhex = 1;
				continue;
			}
			break;

		case 1:
			temp = to_hex(c);
			if (temp < 0) {
				hexhex = 3;
				continue;
			}
			hexval = temp;
			hexhex = 2;
			continue;

		case 2:
			temp = to_hex(c);
			hexhex = 0;
			if (temp < 0) {
				hexhex = 0;
				continue;
			}
			c = (hexval << 4) | temp;
			break;

		case 3:
			hexhex = 0;
			continue;
		}

		switch (utf8) {
		case 0:
			/* Plain ASCII character.  */
			if ((c & 0x80) == 0) {
				utfval = c;
				break;
			}

			/* UTF8 continuation character.  */
			if ((c & 0xc0) == 0x80)
				continue;

			/* UTF8 invalid character.  */
			if ((c & 0xfe) == 0xfe)
				continue;

			if ((c & 0xe0) == 0xc0) {
				utfval = c & 0x1f;
				utf8 = 1;
			} else if ((c & 0xf0) == 0xe0) {
				utfval = c & 0xf;
				utf8 = 2;
			} else if ((c & 0xf8) == 0xf0) {
				utfval = c & 7;
				utf8 = 3;
			} else if ((c & 0xfc) == 0xf8) {
				utfval = c & 3;
				utf8 = 4;
			} else if ((c & 0xfe) == 0xfc) {
				utfval = c & 1;
				utf8 = 5;
			} else {
				syslog(LOG_NOTICE, "invalid unicode char %i??",
				       (unsigned int)c);
			}

			continue;

		default:
			/* We expect a continuation character.  */
			if ((c & 0xc0) != 0x80) {
				utf8 = 0;
				continue;
			}

			utfval = (utfval << 6) | (c & 0x3f);
			if (--utf8)
				continue;
			break;
		}

		// @@@
		if (utfval <= 0x7f)
			*wptr++ = utfval & 0x7f;
	}

	*wptr = 0;
}

static void http_parse_uri_params(struct http_request *req)
{
	char *q;

	q = __cspn(req->uri, "?");
	if (*q != 0) {
		*q = 0;
		q++;
	}

	while (*q != 0) {
		char *nextq;
		char *key;
		char *value;
		struct http_tuple *tup;

		nextq = __cspn(q, "&");
		if (*nextq != 0) {
			*nextq = 0;
			nextq = nextq + 1;
		}

		key = q;

		value = __cspn(key, "=");
		if (*value != 0) {
			*value = 0;
			value = value + 1;
		}

		hexhex_sanitise(key);
		hexhex_sanitise(value);

		tup = http_alloc_tuple(req);
		if (tup != NULL) {
			tup->key = key;
			tup->value = value;
			iv_list_add_tail(&(tup->list), &(req->uri_params));
		}

		q = nextq;
	}
}

static void http_parse_uri(struct http_request *req)
{
	hexhex_sanitise(req->uri);

	if (!strncmp(req->uri, "http://", 7)) {
		char *host;
		char *hostend;

		host = req->uri + 7;
		hostend = __cspn(host, "/");
		if (*hostend) {
			memmove(host - 1, host, hostend - host);
			hostend[-1] = 0;
			req->host = host - 1;
			req->uri = hostend;
		}
	}
}

static void http_parse_first_line(struct http_request *req, char *line)
{
	char *method;
	char *methodend;
	char *uri;
	char *uriend;
	char *version;
	char *versionend;

	method = __spn(line, " ");
	methodend = __cspn(method, " ");
	uri = __spn(methodend, " ");
	uriend = __cspn(uri, " ");
	version = __spn(uriend, " ");
	versionend = __cspn(version, " ");

	if (!*method)
		return;

	*methodend = 0;
	*uriend = 0;
	*versionend = 0;

	req->method = method;
	req->host = "";
	req->uri = uri;
	req->_version = version;

	/* HTTP version is officially "HTTP/[0-9].[0-9]".  */
	if (!strcasecmp(req->_version, "HTTP/1.0"))
		req->http_version = IV_HTTP_VERSION_1_0;
	else if (!strcasecmp(req->_version, "HTTP/1.1"))
		req->http_version = IV_HTTP_VERSION_1_1;
	else
		req->http_version = IV_HTTP_VERSION_0_9;

	req->connection_close = 0;
	if (req->http_version < IV_HTTP_VERSION_1_1)
		req->connection_close = 1;

	req->accept_chunked = 0;
	if (req->http_version >= IV_HTTP_VERSION_1_1)
		req->accept_chunked = 1;

	http_parse_uri_params(req);
	http_parse_uri(req);

	if (req->http_version == IV_HTTP_VERSION_0_9)
		req->done = 1;
}

static void http_parse_header_line(struct http_request *req, char *line)
{
	char *key;
	char *keyend;
	char *value;
	struct http_tuple *tup;

	// @@@ handle continuation lines!!!  (begin with space/tab)

	key = __spn(line, " ");
	keyend = __cspn(key, ":");
	value = __spn(__spn(keyend, ":"), " ");

	if (!*key) {
		req->done = 1;
		return;
	}

	*keyend = 0;

	tup = http_alloc_tuple(req);
	if (tup != NULL) {
		tup->key = key;
		tup->value = value;
		iv_list_add_tail(&(tup->list), &(req->header_params));
	}

	if (!strcasecmp(key, "Connection")) {
		req->connection_close = 0;
		if (strstr(value, "close") != NULL)
			req->connection_close = 1;
	}

	if (!strcasecmp(key, "Host")) {
		/* RFC says we should ignore Host: header if the
		 * request URI had a host component.  */
		if (req->host[0] == 0)
			req->host = value;
	}

	// @@@ Accept chunked encoding test
}

static int conn_commit(struct http_connection *conn, int bytes)
{
	char buf[1024];

	while (bytes) {
		int toread;
		int ret;

		toread = bytes;
		if (toread > sizeof(buf))
			toread = sizeof(buf);

		ret = read(conn->fd.fd, buf, toread);
		if (ret <= 0)
			return -1;

		bytes -= ret;
	}

	return 0;
}

static void http_request_process_data(struct http_request *req)
{
	int bytes_to_commit = 0;

	while (!req->done) {
		char *parse_head = req->inbuf + req->parse_ptr;
		char *endline;
		int bytes_left;
		int line_size;

		bytes_left = req->read_ptr - req->parse_ptr;

		endline = memchr(parse_head, '\n', bytes_left);
		if (endline == NULL) {
			bytes_to_commit += bytes_left;
			break;
		}

		line_size = endline - parse_head + 1;
		bytes_to_commit += line_size;
		req->parse_ptr += line_size;

		*endline = 0;
		if (parse_head != endline && endline[-1] == '\r')
			endline[-1] = 0;

		if (req->method == NULL)
			http_parse_first_line(req, parse_head);
		else
			http_parse_header_line(req, parse_head);
	}

	conn_commit(req->conn, bytes_to_commit);
}

static void http_request_promote(struct http_request *req)
{
	struct http_request_interest *i;

	set_reset_mode(req->conn->fd.fd, 0);
	req->conn->handling_request = 1;
	http_connection_stop_expecting_requests(req->conn);
	req->conn->max_requests--;

	i = find_best_client(req->conn->sock, req);
	if (i == NULL) {
//		fprintf(stderr, "can't find proper client for request "
//			"method:%s host:%s uri:%s version:%s\n", req->method,
//			req->host, req->uri, req->_version);
		http_fail_request(req);
		return;
	}

	iv_list_add_tail(&(req->list), &(i->reqs));
	i->handler(i->cookie);
}

static void http_request_get_data(struct http_request *req)
{
	int bytes_left;
	char *ptr;
	int size;

	ptr = req->inbuf + req->read_ptr;
	size = req->end_ptr - req->read_ptr;

	bytes_left = recv(req->conn->fd.fd, ptr, size, MSG_PEEK);
	if (bytes_left < 0) {
		if (errno != EAGAIN) {
//			perror("recv");
			http_kill_connection(req->conn);
		}
		return;
	}

	if (bytes_left == 0) {
		http_kill_connection(req->conn);
		return;
	}

	req->read_ptr += bytes_left;
	http_request_process_data(req);
	if (req->done) {
		http_request_promote(req);
	} else if (req->read_ptr > req->end_ptr) {
		syslog(LOG_CRIT, "Attempted buffer overflow");
		set_reset_mode(req->conn->fd.fd, 1);
		http_kill_connection(req->conn);
	}
}

static void http_connection_get_data(void *_conn)
{
	struct http_connection *conn = (struct http_connection *)_conn;

	if (conn->current == NULL && 1) {
		http_attach_new_request(conn);
		if (conn->current == NULL) {
			// @@@
			return;
		}
	}

	http_request_get_data(conn->current);
}







/************/
int http_register_interest(struct http_request_interest *i)
{
	struct http_listening_socket *s;
	struct in_addr ip;
	int port;

	if (!inet_aton(i->ip, &ip))
		return -1;

	if (sscanf(i->port, "%d", &port) != 1)
		return -1;

	if (port < 0 || port > 65535)
		return -1;

	s = find_http_socket(ip.s_addr, port);
	if (s == NULL)
		return -1;

	INIT_IV_LIST_HEAD(&(i->list));
	i->sock = s;
	INIT_IV_LIST_HEAD(&(i->reqs));

	iv_list_add_tail(&(i->list), &(s->interests));

	return 0;
}

void http_unregister_interest(struct http_request_interest *i)
{
	struct iv_list_head *lh;
	struct iv_list_head *lh2;

	iv_list_for_each_safe (lh, lh2, &(i->reqs))
		iv_list_del_init(lh);

	iv_list_del(&(i->list));
	if (iv_list_empty(&(i->sock->interests)))
		destroy_http_socket(i->sock);
}

int http_dequeue_request(struct http_request_interest *i,
			 struct http_request **req)
{
	if (!iv_list_empty(&(i->reqs))) {
		struct http_request *r;

		r = iv_list_entry(i->reqs.next, struct http_request, list);
		iv_list_del(&(r->list));
		*req = r;
		return 1;
	}

	return 0;
}

static char *http_find_tuple(struct iv_list_head *head, char *key)
{
	struct iv_list_head *lh;

	iv_list_for_each (lh, head) {
		struct http_tuple *t;

		t = iv_list_entry(lh, struct http_tuple, list);
		if (!strcmp(t->key, key))
			return t->value;
	}

	return NULL;
}

char *http_request_get_uri_param(struct http_request *req, char *key)
{
	return http_find_tuple(&(req->uri_params), key);
}

char *http_request_get_header_param(struct http_request *req, char *key)
{
	return http_find_tuple(&(req->header_params), key);
}

int http_request_get_peername(struct http_request *req,
			      struct sockaddr *name,
			      socklen_t *namelen)
{
	struct http_connection *conn = req->conn;
	int ret;

	ret = -EINVAL;
	if (conn != NULL) {
		int len;

		len = *namelen;
		if (conn->peername_length < len)
			len = conn->peername_length;

		memcpy(name, &(conn->peername), len);
		ret = 0;
	}

	return ret;
}

void http_request_set_status_code(struct http_request *req, int code)
{
	req->status_code = code;
}

void http_request_set_content_length(struct http_request *req, int len)
{
	req->content_length = len;
}

void http_request_set_content_type(struct http_request *req, char *type)
{
	req->content_type = strdup(type);
}

void http_request_set_server(struct http_request *req, char *server)
{
	req->server = strdup(server);
}

static char *http_status_code_name(int numeric)
{
	switch (numeric) {
	case 100:	return "Continue";
	case 101:	return "Switching Protocols";

	case 200:	return "OK";
	case 201:	return "Created";
	case 202:	return "Accepted";
	case 203:	return "Non-Authoritative Information";
	case 204:	return "No Content";
	case 205:	return "Reset Content";
	case 206:	return "Partial Content";

	case 300:	return "Multiple Choices";
	case 301:	return "Moved Permanently";
	case 302:	return "Found";
	case 303:	return "See Other";
	case 304:	return "Not Modified";
	case 305:	return "Use Proxy";
	case 307:	return "Temporary Redirect";

	case 400:	return "Bad Request";
	case 401:	return "Unauthorized";
	case 402:	return "Payment Required";
	case 403:	return "Forbidden";
	case 404:	return "Not found";
	case 405:	return "Method Not Allowed";
	case 406:	return "Not Acceptable";
	case 407:	return "Proxy Authentication Required";
	case 408:	return "Request Timeout";
	case 409:	return "Conflict";
	case 410:	return "Gone";
	case 411:	return "Length Required";
	case 412:	return "Precondition Failed";
	case 413:	return "Request Entity Too Large";
	case 414:	return "Request-URI Too Long";
	case 415:	return "Unsupported Media Type";
	case 416:	return "Requested Range Not Satisfiable";
	case 417:	return "Expectation Failed";

	case 500:	return "Internal Server Error";
	case 501:	return "Not Implemented";
	case 502:	return "Bad Gateway";
	case 503:	return "Service Unavailable";
	case 504:	return "Gateway Timeout";
	case 505:	return "HTTP Version Not Supported";
	}

	return "-";
}

static void http_send_headers(struct http_request *req)
{
	char headers[1024];
	char line[1024];

	headers[0] = 0;

	// @@@@@@@@@@@@ strcat @@@@@@@@@@@

	snprintf(line, 1024, "HTTP/1.1 %3d %s\r\n", req->status_code,
		 http_status_code_name(req->status_code));
	strcat(headers, line);

	if (req->server != NULL) {
		snprintf(line, 1024, "Server: %s\r\n", req->server);
	} else {
		snprintf(line, 1024, "Server: http_server\r\n");
	}
	strcat(headers, line);

	switch (req->reply_mode) {
	case IV_HTTP_REPLY_CONNECTION_CLOSE:
		if (!req->connection_close) {
			snprintf(line, 1024, "Connection: close\r\n");
			strcat(headers, line);
		}
		break;

	case IV_HTTP_REPLY_CHUNKED:
		snprintf(line, 1024, "Transfer-Encoding: chunked\r\n");
		strcat(headers, line);
		break;
	}

	if (req->content_length != -1) {
		snprintf(line, 1024, "Content-Length: %d\r\n",
			 req->content_length);
		strcat(headers, line);
	}

	if (req->content_type != NULL) {
		snprintf(line, 1024, "Content-Type: %s\r\n",
			 req->content_type);
		strcat(headers, line);
	}

	strcat(headers, "\r\n");
	write(req->conn->fd.fd, headers, strlen(headers));
}

int http_request_start_reply(struct http_request *req)
{
	if (req->connection_close)
		req->reply_mode = IV_HTTP_REPLY_CONNECTION_CLOSE;
	else if (!req->conn->max_requests)
		req->reply_mode = IV_HTTP_REPLY_CONNECTION_CLOSE;
	else if (req->content_length != -1)
		req->reply_mode = IV_HTTP_REPLY_CONTENT_LENGTH;
	else if (req->accept_chunked)	// @@@
		req->reply_mode = IV_HTTP_REPLY_CHUNKED;
	else
		req->reply_mode = IV_HTTP_REPLY_CONNECTION_CLOSE;

	if (req->http_version >= IV_HTTP_VERSION_1_0)
		http_send_headers(req);

	return 0;
}

// @@@ chunk buffering!!!
int http_request_write(struct http_request *req, char *buf, size_t len)
{
	int ret;

	if (req->reply_mode == IV_HTTP_REPLY_CHUNKED) {
		char length[16];

		snprintf(length, 16, "%x\r\n", (int)len);
		write(req->conn->fd.fd, length, strlen(length));	// @@@
	} else if (req->reply_mode == IV_HTTP_REPLY_CONTENT_LENGTH) {
		int quotum = req->content_length - req->content_sent;
		if (len > quotum) {
			syslog(LOG_ALERT, "chopping http write %d->%d",
			       (int)len, quotum);
			len = quotum;
		}
	}

	ret = write(req->conn->fd.fd, buf, len);
	if (ret > 0) {
		if (req->content_length != -1)
			req->content_sent += ret;
		if (req->reply_mode == IV_HTTP_REPLY_CHUNKED)
			write(req->conn->fd.fd, "\r\n", 2);
	}

	return ret;
}

static int fill(int fd, int bytes)
{
	char buf[1024];

	memset(buf, 0, sizeof(buf));
	while (bytes) {
		int towrite;
		int ret;

		towrite = sizeof(buf);
		if (towrite > bytes)
			bytes = towrite;

		ret = write(fd, buf, towrite);
		if (ret <= 0)
			return 1;

		bytes -= ret;
	}

	return 0;
}

int http_request_end_reply(struct http_request *req)
{
	int should_close;

	should_close = 0;

	if (req->content_length != -1)
		should_close = fill(req->conn->fd.fd,
			req->content_length - req->content_sent);

	switch (req->reply_mode) {
	case IV_HTTP_REPLY_CHUNKED:
		// @@@ implement proper trailer sending support?
		write(req->conn->fd.fd, "0\r\n\r\n", 5);
		break;

	case IV_HTTP_REPLY_CONNECTION_CLOSE:
		should_close = 1;
		break;
	}

	if (!should_close) {
		struct http_connection *conn = req->conn;

		http_kill_request(req);
		conn->handling_request = 0;
		
		http_connection_start_expecting_requests(conn);
	} else {
		http_kill_connection(req->conn);
	}

	return 0;
}

static void http_fail_request(struct http_request *req)
{
	char *msg;

	msg = "The requested URL was not found on this server.<p>\r\n";

	http_request_set_status_code(req, 404);
	http_request_set_content_length(req, strlen(msg));
	http_request_set_content_type(req, "text/html");
	http_request_start_reply(req);
	http_request_write(req, msg, strlen(msg));
	http_request_end_reply(req);
}

// @@@ test me!
int http_request_steal_socket(struct http_request *req, int send_headers)
{
	struct http_connection *conn = req->conn;
	int fd;

	req->reply_mode = IV_HTTP_REPLY_CONNECTION_CLOSE;
	if (send_headers && req->http_version >= IV_HTTP_VERSION_1_0)
		http_send_headers(req);
	req->conn = NULL;

	conn->current = NULL;
	fd = conn->fd.fd;
	__http_kill_connection(conn, 0);

	return fd;
}

void http_request_finish_request(struct http_request *req)
{
	http_kill_request(req);
}
