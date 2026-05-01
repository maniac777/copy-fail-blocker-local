bpf:
	clang -g -O2 -target bpf -c blocker.c -o blocker.o

loader:
	bpftool gen skeleton blocker.o > blocker.skel.h
	gcc -Wall loader.c -o loader -lbpf -lelf -lz

all: bpf loader

clean:
	rm -f blocker.o
	rm -f blocker.skel.h
	rm -f loader

