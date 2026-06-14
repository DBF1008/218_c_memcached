# gcc -g -Wall -Werror -pedantic -o example example.c mcmc.c
PREFIX=/usr/local

all:
	gcc -g -O2 -Wall -Werror -pedantic -o example example.c mcmc.c
	gcc -g -O2 -Wall -Werror -pedantic -c mcmc.c

# Regression tests for ASCII multiget / multi-line response parsing.
# -Werror is intentionally omitted: the vendored mcmc.c emits a pre-existing
# -Wdiscarded-qualifiers warning (memchr on a const buffer) that is unrelated
# to these tests and predates them. -Wall -pedantic still vet the test code.
test:
	gcc -g -O2 -Wall -pedantic -o t_multiget t_multiget.c mcmc.c
	./t_multiget

clean:
	rm -f example mcmc.o t_multiget

dist: clean

distdir:
