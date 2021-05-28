xdp_mon_kern.o: src/xdp_mon_kern.c src/common.h
	clang -O2 -target bpf -o $@ -c $<

xdp_loader: src/xdp_mon_user.c src/common.h
	gcc -lbpf -lpthread -g -o $@ $<

all: xdp_mon_kern.o xdp_loader

run:
	./xdp_loader

PHONY: all run
