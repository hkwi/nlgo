package main

import (
	"github.com/hkwi/nlgo"
	"log"
	"syscall"
	"unsafe"
)

func main() {
	sock := nlgo.NlSocketAlloc()
	if err := nlgo.NlConnect(sock, syscall.NETLINK_ROUTE); err != nil {
		panic(err)
	}
	if err := nlgo.NlSocketAddMembership(sock, syscall.RTNLGRP_LINK); err != nil {
		panic(err)
	}
	buf := make([]byte, syscall.Getpagesize())
	for {
		var blk []byte
		if nn, _, err := syscall.Recvfrom(sock.Fd, buf, syscall.MSG_TRUNC); err != nil {
			panic(err)
		} else if nn > len(buf) {
			panic("out of recv buf")
		} else {
			blk = buf[:nn]
		}
		if msgs, err := syscall.ParseNetlinkMessage(blk); err != nil {
			panic(err)
		} else {
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.RTM_NEWLINK, syscall.RTM_DELLINK, syscall.RTM_GETLINK:
					ifinfo := (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0]))
					if attrs, err := nlgo.RouteLinkPolicy.Parse(msg.Data[nlgo.NLA_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
						panic(err)
					} else {
						log.Print("ifinfomsg=", ifinfo, " attrs=", attrs)
					}
				default:
					log.Print("unhandled msg")
				}
			}
		}
	}
}
