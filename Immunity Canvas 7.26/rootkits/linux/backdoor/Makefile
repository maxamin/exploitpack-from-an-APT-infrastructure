
all:
	gcc -o immrtbkd immbkd.c md5.c
	strip immrtbkd
debug:
	gcc -o immrtbkd immbkd.c md5.c -ggdb -Wall -DDEBUG
clean:
	rm -rf immrtbkd
