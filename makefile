all: great
great:
	echo "Program can be started\n Give proper commands"

installPBC:
	wget "https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz"
	tar xvzf pbc-0.5.14.tar.gz
	cd pbc-0.5.14/
	sudo apt-get install m4
	sudo apt-get install flex
	sudo apt-get install bison
	./configure --prefix=$HOME/.local
	sudo make
	sudo make install

pbc:
	gcc -g -Wall tests/pbc_test.c -o pbc_test.o  -L. -lpbc -lgmp
	LD_LIBRARY_PATH=/usr/local/lib  ./pbc_test.o

myBgn:
	gcc -g -Wall tests/myBgn_test.c src/myBgn.c -o myBgn_test.o  -L. -lpbc -lgmp -I include
	LD_LIBRARY_PATH=/usr/local/lib  ./myBgn_test.o

slp1:
	gcc -g -Wall tests/SLP1_test.c src/SLP1.c src/myBgn.c -o SLP1_test.o  -L. -lpbc -lgmp -I include
	./SLP1_test.o data/example-graph 100 128

slp2:
	gcc -g -Wall tests/SLP2_test.c src/SLP2.c src/myBgn.c -o SLP2_test.o  -L. -lpbc -lgmp -I include
	./SLP2_test.o data/example-graph 100 128

clean:
	gvfs-trash *.o
