package nlgo

import (
	"fmt"
	"sync"
	"syscall"
)

type RtMessage struct {
	Message  syscall.NetlinkMessage
	Controls []syscall.SocketControlMessage
	Error    error
}

type RtListener interface {
	RtListen(RtMessage)
}

type RtHub struct {
	Sock      *NlSock
	Lock      *sync.Mutex
	Unicast   map[uint32]chan RtMessage
	Multicast map[uint32][]RtListener
}

func NewRtHub() (RtHub, error) {
	self := RtHub{
		Sock:    NlSocketAlloc(),
		Lock:    &sync.Mutex{},
		Unicast: make(map[uint32]chan RtMessage),
	}
	if err := NlConnect(self.Sock, syscall.NETLINK_ROUTE); err != nil {
		return self, err
	}
	go func() {
		for {
			var merr error
			var messages []syscall.NetlinkMessage
			var controls []syscall.SocketControlMessage

			buf := make([]byte, syscall.Getpagesize())
			oob := make([]byte, syscall.Getpagesize())
			if bufN, oobN, _, _, err := syscall.Recvmsg(self.Sock.Fd, buf, oob, syscall.MSG_TRUNC); err != nil {
				merr = err
			} else if bufN > len(buf) {
				merr = err
			} else if oobN > len(oob) {
				merr = err
			} else if msgs, err := syscall.ParseNetlinkMessage(buf[:bufN]); err != nil {
				merr = err
			} else if ctrls, err := syscall.ParseSocketControlMessage(oob[:oobN]); err != nil {
				merr = err
			} else {
				messages = msgs
				controls = ctrls
			}
			for _, message := range messages {
				msg := RtMessage{
					Message:  message,
					Controls: controls,
					Error:    merr,
				}
				seq := message.Header.Seq
				mtype := message.Header.Type
				if seq == 0 {
					self.Lock.Lock()
					listeners := self.Multicast[message.Header.Pid]
					self.Lock.Unlock()

					for _, listener := range listeners {
						listener.RtListen(msg)
					}
				} else {
					self.Lock.Lock()
					listener := self.Unicast[seq]
					self.Lock.Unlock()

					if listener != nil {
						listener <- msg
						if mtype == syscall.NLMSG_DONE || mtype == syscall.NLMSG_ERROR {
							delete(self.Unicast, seq)
							close(listener)
						}
					}
				}
			}
		}
	}()
	return self, nil
}

func (self RtHub) Request(cmd uint16, flags uint16, payload []byte, attr AttrList) (chan RtMessage, error) {
	res := make(chan RtMessage)

	var msg []byte
	switch cmd {
	case syscall.RTM_NEWLINK, syscall.RTM_DELLINK, syscall.RTM_GETLINK:
		msg = make([]byte, NLMSG_ALIGN(syscall.SizeofIfInfomsg))
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR, syscall.RTM_GETADDR:
		msg = make([]byte, NLMSG_ALIGN(syscall.SizeofIfAddrmsg))
	case syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_GETROUTE,
		syscall.RTM_NEWRULE, syscall.RTM_DELRULE, syscall.RTM_GETRULE:
		msg = make([]byte, NLMSG_ALIGN(syscall.SizeofRtMsg))
	case syscall.RTM_NEWNEIGH, syscall.RTM_DELNEIGH, syscall.RTM_GETNEIGH:
		msg = make([]byte, NLMSG_ALIGN(SizeofNdmsg))
	case syscall.RTM_NEWQDISC, syscall.RTM_DELQDISC, syscall.RTM_GETQDISC,
		syscall.RTM_NEWTCLASS, syscall.RTM_DELTCLASS, syscall.RTM_GETTCLASS,
		syscall.RTM_NEWTFILTER, syscall.RTM_DELTFILTER, syscall.RTM_GETTFILTER:
		msg = make([]byte, NLMSG_ALIGN(SizeofTcmsg))
	default:
		close(res)
		return res, fmt.Errorf("unsupported")
	}
	copy(msg, payload)
	msg = append(msg, attr.Bytes()...)

	self.Lock.Lock()
	defer self.Lock.Unlock()
	self.Unicast[self.Sock.SeqNext] = res
	return res, NlSendSimple(self.Sock, cmd, flags, msg)
}

func (self RtHub) Add(group uint32, listener RtListener) error {
	self.Lock.Lock()
	defer self.Lock.Unlock()

	if len(self.Multicast[group]) == 0 {
		if err := NlSocketAddMembership(self.Sock, int(group)); err != nil {
			return err
		}
	}
	self.Multicast[group] = append(self.Multicast[group], listener)
	return nil
}

func (self RtHub) Remove(group uint32, listener RtListener) error {
	self.Lock.Lock()
	defer self.Lock.Unlock()

	var active []RtListener
	for _, li := range self.Multicast[group] {
		if li != listener {
			active = append(active, li)
		}
	}
	self.Multicast[group] = active

	if len(active) == 0 {
		if err := NlSocketDropMembership(self.Sock, int(group)); err != nil {
			return err
		}
	}
	return nil
}
