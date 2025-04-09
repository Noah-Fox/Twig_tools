CFLAGS = -Wall -Werror
CC=g++

twig: twig.cc
	${CC} ${CFLAGS} -o twig twig.cc

clean:
	rm twig

