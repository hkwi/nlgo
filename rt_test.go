// +build linux

package nlgo

import (
	"log"
	"syscall"
	"unsafe"
)

// This basic rtnetlink example lists up link interfaces.
func Example() {
	sock := NlSocketAlloc()
	defer NlSocketFree(sock)
	if err := NlConnect(sock, syscall.NETLINK_ROUTE); err != nil {
		panic(err)
	}
	req := make([]byte, NLMSG_ALIGN(syscall.SizeofIfInfomsg))
	if err := NlSendSimple(sock, syscall.RTM_GETLINK, syscall.NLM_F_DUMP, req); err != nil {
		panic(err)
	}
	func() {
		for {
			buf := make([]byte, syscall.Getpagesize())
			if nn, _, err := syscall.Recvfrom(sock.Fd, buf, syscall.MSG_TRUNC); err != nil {
				panic(err)
			} else if nn > len(buf) {
				panic("out of recv buf")
			} else {
				buf = buf[:nn]
			}
			if msgs, err := syscall.ParseNetlinkMessage(buf); err != nil {
				panic(err)
			} else {
				for _, msg := range msgs {
					switch msg.Header.Type {
					case syscall.RTM_NEWLINK:
						ifinfo := (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0]))
						if attrs, err := RouteLinkPolicy.Parse(msg.Data[NLA_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
							panic(err)
						} else {
							log.Print("ifinfomsg=", ifinfo, " attrs=", attrs)
						}
					case syscall.NLMSG_DONE:
						return
					default:
						log.Print("unhandled msg", msg.Header)
					}
				}
			}
		}
	}()
}

// This is RTNLGRP_LINK listener example. RTNLGRP_LINK is newer version of RTMGRP_LINK.
func ExampleNlSocketAddMembership() {
	sock := NlSocketAlloc()
	defer NlSocketFree(sock)
	if err := NlConnect(sock, syscall.NETLINK_ROUTE); err != nil {
		panic(err)
	}
	if err := NlSocketAddMembership(sock, syscall.RTNLGRP_LINK); err != nil {
		panic(err)
	}
	for {
		buf := make([]byte, syscall.Getpagesize())
		if nn, _, err := syscall.Recvfrom(sock.Fd, buf, syscall.MSG_TRUNC); err != nil {
			panic(err)
		} else if nn > len(buf) {
			panic("out of recv buf")
		} else {
			buf = buf[:nn]
		}
		if msgs, err := syscall.ParseNetlinkMessage(buf); err != nil {
			panic(err)
		} else {
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.RTM_NEWLINK, syscall.RTM_DELLINK, syscall.RTM_GETLINK:
					ifinfo := (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0]))
					if attrs, err := RouteLinkPolicy.Parse(msg.Data[NLA_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
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
