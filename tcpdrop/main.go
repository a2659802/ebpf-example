//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf drop.c -- -I../headers

// var (
// 	linkName = flag.String("link", "", "container link name here to attach bpf prog")
// )

// func main() {
// 	flag.Parse()
// 	if len(*linkName) == 0 {
// 		log.Fatal("link is required")
// 	}

// 	// Allow the current process to lock memory for eBPF resources.
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Fatal(err)
// 	}

// 	// Load pre-compiled programs and maps into the kernel.
// 	objs := bpfObjects{}
// 	if err := loadBpfObjects(&objs, nil); err != nil {
// 		log.Fatalf("loading objects: %v", err)
// 	}
// 	defer objs.Close()

// }

// func attach(link int, progFD int) {
// 	netlink.QdiscAdd(&netlink.PfifoFast{QdiscAttrs: netlink.QdiscAttrs{
// 		LinkIndex: link,
// 		Parent:    0,
// 		Handle:    0,
// 	}})
// 	netlink.FilterAdd(&netlink.BpfFilter{
// 		FilterAttrs: netlink.FilterAttrs{
// 			LinkIndex: link,
// 			Handle:    0,
// 			Parent:    0,
// 		},
// 		Fd: progFD,
// 	})
// }
