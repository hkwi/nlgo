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
	sock      *NlSock
	lock      *sync.Mutex
	unicast   map[uint32]chan RtMessage
	multicast map[uint32][]RtListener
}

func NewRtHub() (*RtHub, error) {
	self := &RtHub{
		sock:      NlSocketAlloc(),
		lock:      &sync.Mutex{},
		unicast:   make(map[uint32]chan RtMessage),
		multicast: make(map[uint32][]RtListener),
	}
	if err := NlConnect(self.sock, syscall.NETLINK_ROUTE); err != nil {
		NlSocketFree(self.sock)
		return nil, err
	}
	go func() {
		for {
			var merr error
			var messages []syscall.NetlinkMessage
			var controls []syscall.SocketControlMessage

			buf := make([]byte, syscall.Getpagesize())
			oob := make([]byte, syscall.Getpagesize())
			if bufN, oobN, _, _, err := syscall.Recvmsg(self.sock.Fd, buf, oob, syscall.MSG_TRUNC); err != nil {
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
					var listeners []RtListener // rtnetlink multicast does not set pid properly by historical reason.
					self.lock.Lock()
					for _, s := range self.multicast {
						listeners = append(listeners, s...)
					}
					self.lock.Unlock()

					for _, listener := range listeners {
						listener.RtListen(msg)
					}
				} else {
					self.lock.Lock()
					listener := self.unicast[seq]
					self.lock.Unlock()

					if listener != nil {
						listener <- msg
						if mtype == syscall.NLMSG_DONE || mtype == syscall.NLMSG_ERROR {
							delete(self.unicast, seq)
							close(listener)
						}
					}
				}
			}
		}
	}()
	return self, nil
}

func (self RtHub) Request(cmd uint16, flags uint16, payload []byte, attr AttrList) ([]RtMessage, error) {
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
		return nil, fmt.Errorf("unsupported")
	}
	copy(msg, payload)
	msg = append(msg, attr.Bytes()...)

	self.lock.Lock()
	self.unicast[self.sock.SeqNext] = res
	self.lock.Unlock()

	if err := NlSendSimple(self.sock, cmd, flags, msg); err != nil {
		return nil, err
	}

	var ret []RtMessage
	for r := range res {
		ret = append(ret, r)
	}
	return ret, nil
}

func (self RtHub) Add(group uint32, listener RtListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	if len(self.multicast[group]) == 0 {
		if err := NlSocketAddMembership(self.sock, int(group)); err != nil {
			return err
		}
	}
	self.multicast[group] = append(self.multicast[group], listener)
	return nil
}

func (self RtHub) Remove(group uint32, listener RtListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	var active []RtListener
	for _, li := range self.multicast[group] {
		if li != listener {
			active = append(active, li)
		}
	}
	self.multicast[group] = active

	if len(active) == 0 {
		if err := NlSocketDropMembership(self.sock, int(group)); err != nil {
			return err
		}
	}
	return nil
}
