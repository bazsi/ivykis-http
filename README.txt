Limitations:
============

input buffer:
-------------
* memory allocated for requests + header meta data + uri params metadata is
  limited to 4k

* every metadata takes 16 (32bit) or 32 (64bit) bytes from the input buffer

* headers & uri parameters that would overflow this buffer are simply
  dropped

* POST data is not read into this buffer

Request body:
-------------
* the request body is completely ignored by this implementation, if the
  application wants POST data it has to read it from the input stream/decode
  it on its own

Headers
-------
* continuation lines in headers are not supported

Missing
-------
* POST handling is completely missing and is not possible to implement at
  the application side:
   - no access to the fd
   - Content-Length/Transfer-Encoding is only optionally available (in case
     the request parser didn't drop them because of buffer shortage)

* output buffering is not implemented but should be

* not possible to send additional headers with a response, except for those
  that directly influence response transfer (Connection, Transfer-Encoding &
  Content-Length)

* ipv6 support, it strictly relies on struct sockaddr_in and AF_INET
  everywhere

* configuration stuff, these are hard-coded:
  - the number of requests served on a single connection
    (stored in the max_requests_per_connection variable)
  - the length of the listen() backlog is 6
  - 

* interests can only be registered on IP addresses and not hostnames

Bugs
----
* [FIXED] \r is assumed to be an end of line, even when CRLF was split between two
  packets.
* possible buffer overflow with Content-Type/Server header because the code
  uses strcat() to a limited size buffer
* [FIXED] doesn't call shutdown(), so the response data may not reach the client
* [FIXED] off-by-one in request buffer size validation


