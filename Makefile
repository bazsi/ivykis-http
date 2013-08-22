
http_test: http_test.c http_client.c http_server.c
	gcc -Iivykis/src/include -Wall -O2  -g -c http_test.c
	gcc -Iivykis/src/include -Wall -O2  -g -c http_client.c
	gcc -Iivykis/src/include -Wall -O2  -g -c http_server.c
	gcc -Iivykis/src/include -Wall -O2  -g -o http_test http_test.o http_client.o http_server.o ivykis/src/.libs/libivykis.a -lpthread
