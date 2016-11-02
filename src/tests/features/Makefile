all: libfeatures.so

libfeatures.so: *.c
	gcc -Wall -O2 -g -shared $^ -o $@ -Iinclude -fPIC -L. -llight_pcapng

clean:
	rm -rf libfeatures.so