#include "http_server.h"
#include <stdio.h>
#include <string.h>

struct http_server
{
  struct http_request_interest hri;
};

static struct http_server server;
static int count = 0;

static void
request_arrived(void *cookie)
{
  struct http_request *hr;

  if (!http_dequeue_request(&server.hri, &hr))
    {
      fprintf(stderr, "Unable to dequeue HTTP request\n");
      return;
    }
  printf("request has arrived\n%s %s\n", hr->method, hr->uri);
  
  http_request_set_status_code(hr, 200);
  http_request_set_content_length(hr, 16);
  http_request_set_content_type(hr, "text/plain");
  http_request_set_server(hr, "My tiny little web server");
  http_request_start_reply(hr);
  http_request_write(hr, "0123456789ABCDEF", 16);
  http_request_end_reply(hr);
  if (count++ == 4)
    iv_quit();
}

static int
start_server(void)
{
  struct http_request_interest *hri = &server.hri;
  int rc;
  
  memset(&server, 0, sizeof(server));

  hri->ip = "0.0.0.0";
  hri->port = "8080";
  hri->method = "GET";
  hri->host = NULL;
  hri->uri = NULL;
  hri->cookie = &server;
  hri->handler = request_arrived;

  rc = http_register_interest(hri);
  if (rc < 0)
    return 1;
  return 0;
}

static void
stop_server(void)
{
  http_unregister_interest(&server.hri);
}

int main(int argc, char *argv[])
{
  iv_init();
  if (start_server() < 0)
    return 1;
  iv_main();
  stop_server();
  iv_deinit();
  return 0;
}
