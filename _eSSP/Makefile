LIBS=-lstdc++ -lpthread

.PHONY: clean

libessp.so:

%.o:%.c
	$(CC) -c -fPIC -ggdb -g3 -o $@ $^

libessp.so: init.o ssp_helpers.o linux.o update.o lib/bin/libitlssp.a
	$(CC) -shared -fPIC -ggdb -g3 -Wall -Wextra -Wl,-soname,libessp.so.1 -o $@ $^

lib/bin/libitlssp.a:
	mkdir -p lib/bin/shared
	$(MAKE) -C lib

clean:
	rm -f *.o *.so
	rm -f lib/*.o lib/*.so
