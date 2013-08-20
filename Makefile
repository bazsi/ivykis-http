
http_test: http_test.c http_client.c http_server.c
	gcc -Iivykis/src/include -Wall -O2 -g -o http_test http_test.c http_client.c http_server.c ivykis/src/.libs/libivykis.a -lpthread
