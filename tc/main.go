//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

//go:generate $BPF_CLANG -target bpf -O2 -c lb.c -o obj.o -I../headers -I /usr/include/x86_64-linux-gnu
