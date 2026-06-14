# gcc -g -Wall -Werror -pedantic -o example example.c mcmc.c
PREFIX=/usr/local

all:
	gcc -g -O2 -Wall -Werror -pedantic -o example example.c mcmc.c
	gcc -g -O2 -Wall -Werror -pedantic -c mcmc.c

test: test_mcmc
	./test_mcmc

test_mcmc: test_mcmc.c mcmc.c mcmc.h
	gcc -g -O2 -Wall -Werror -pedantic -o test_mcmc test_mcmc.c mcmc.c

clean:
	rm -f example mcmc.o test_mcmc

dist: clean

distdir:

