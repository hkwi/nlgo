package rtlink

import (
	"fmt"
	"github.com/hkwi/nlgo"
	"syscall"
	"unsafe"
)

type Listener struct {
	sock  *nlgo.NlSock
	init  bool
	start uint32
}

func NewListener() (*Listener, error) {
	sock := nlgo.NlSocketAlloc()
	sock.Flags = nlgo.NL_NO_AUTO_ACK
	if err := nlgo.NlConnect(sock, syscall.NETLINK_ROUTE); err != nil {
		nlgo.NlSocketFree(sock)
		return nil, err
	}
	if err := nlgo.NlSocketAddMembership(sock, syscall.RTNLGRP_LINK); err != nil {
		nlgo.NlSocketFree(sock)
		return nil, err
	}

	start := sock.SeqNext
	if err := nlgo.NlSendSimple(sock, syscall.RTM_GETLINK, syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP, make([]byte, syscall.SizeofIfInfomsg)); err != nil {
		nlgo.NlSocketFree(sock)
		return nil, err
	}
	return &Listener{
		sock:  sock,
		start: start,
	}, nil

}

type Message struct {
	Header syscall.NlMsghdr
	syscall.IfInfomsg
	Attrs nlgo.NlaValue
}

// Recv returns RTM_NEWLINK, RTM_DELLINK sequence in system call including initial dump.
func (self *Listener) Recv() ([]Message, error) {
	buf := make([]byte, syscall.Getpagesize())
	for {
		// we may pass cmsg (oob and or MSG_TRUNC) here ... but what can we treat them after all?
		if n, _, err := syscall.Recvfrom(self.sock.Fd, buf, 0); err != nil {
			if e, ok := err.(syscall.Errno); ok && e.Temporary() {
				continue
			}
			return nil, err
		} else if msgs, err := syscall.ParseNetlinkMessage(buf[:n]); err != nil {
			return nil, err
		} else {
			var ret []Message
			for _, msg := range msgs {
				if !self.init {
					if msg.Header.Seq != self.start {
						continue
					}
					self.init = true
				}
				switch msg.Header.Type {
				case syscall.NLMSG_NOOP:
					return nil, fmt.Errorf("should not happen: NLMSG_NOOP")
				case syscall.NLMSG_ERROR:
					nle := (*syscall.NlMsgerr)(unsafe.Pointer(&msg.Data[0]))
					if nle.Error == 0 { // 0 for "ACK"
						return nil, fmt.Errorf("should not happen: ACK/NLMSG_ERROR")
					} else {
						return nil, fmt.Errorf("NLMSG_ERROR %v", msg)
					}
				case syscall.NLMSG_DONE:
					return ret, nil
				case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
					if attrs, err := nlgo.RouteLinkPolicy.Parse(msg.Data[nlgo.NLMSG_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
						return nil, err
					} else {
						ret = append(ret, Message{
							Header:    msg.Header,
							IfInfomsg: *(*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0])),
							Attrs:     attrs,
						})
					}
				default:
					return nil, fmt.Errorf("should not happen: unknown %v", msg.Header)
				}
			}
			return ret, nil
		}
	}
}
