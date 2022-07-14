//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os/exec"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// const DEBUGFS = "/sys/kernel/debug/tracing/"

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf sockex1.c -- -I../headers -I /usr/include/x86_64-linux-gnu

// const mapKey uint32 = 0

func main() {

	// Name of the kernel function to trace.
	// fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	sock := OpenRawSock("lo")
	if err := AttachSocketFilter(sock, objs.BpfProg1); err != nil {
		panic(err)
	}

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	exec.Command("ping", "-4", "-c5", "localhost").Start()

	var key uint32
	for range ticker.C {
		var tcp_cnt, udp_cnt, icmp_cnt uint64

		key = unix.IPPROTO_TCP
		if err := objs.Mymap.Lookup(&key, &tcp_cnt); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		key = unix.IPPROTO_UDP
		if err := objs.Mymap.Lookup(&key, &udp_cnt); err != nil {
			log.Fatalf("reading map udp: %v", err)
		}
		key = unix.IPPROTO_ICMP
		if err := objs.Mymap.Lookup(&key, &icmp_cnt); err != nil {
			log.Fatalf("reading map icmp: %v", err)
		}

		fmt.Printf("TCP %v UPD %v ICMP %v bytes \n", tcp_cnt, udp_cnt, icmp_cnt)

	}

	// ReadSocket(sock)
}

func htons(in uint16) uint16 {
	short := [2]byte{}
	binary.BigEndian.PutUint16(short[:], in)
	return *((*uint16)(unsafe.Pointer(&short[0])))
}

func OpenRawSock(linkName string) int {
	proto := htons(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	// fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		panic(err)
	}
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		panic(err)
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  link.Attrs().Index,
		Protocol: proto,
	}
	err = unix.Bind(fd, addr)
	if err != nil {
		panic(err)
	}

	return fd
}

func AttachSocketFilter(fd int, prog *ebpf.Program) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD())
}

func ReadSocket(fd int) {
	fmt.Println("read socket")
	var buf [4086]byte
	for {
		nread, err := unix.Read(fd, buf[:])
		if err != nil {
			fmt.Printf("error read %v\n", err.Error())
			time.Sleep(time.Second)
			continue
		}
		fmt.Println(nread)
	}
}
