// +build linux

package nlgo

import (
	"fmt"
	"log"
	"sync"
	"syscall"
	"unsafe"
)

type GenlMessage struct {
	Header  syscall.NlMsghdr
	Genl    *GenlMsghdr
	Family  string
	Payload []byte // fixe header + attributes
	Error   error
}

type GenlListener interface {
	GenlListen(GenlMessage)
}

type groupKey struct {
	Family string
	Name   string
}

// GenlHub is generic netlink version of RtHub.
type GenlHub struct {
	sock       *NlSock
	lock       *sync.Mutex
	familyIds  map[uint16]GenlFamily
	groupIds   map[uint32]GenlGroup
	membership []uint32
	unicast    map[uint32]chan GenlMessage
	multicast  map[groupKey][]GenlListener
}

func (self *GenlHub) join(group uint32) error {
	for _, member := range self.membership {
		if member == group {
			return nil
		}
	}
	self.membership = append(self.membership, group)
	return NlSocketAddMembership(self.sock, int(group))
}

func (self *GenlHub) leave(group uint32) error {
	var active []uint32
	hit := false
	for _, member := range self.membership {
		if member == group {
			hit = true
		} else {
			active = append(active, member)
		}
	}
	self.membership = active
	if hit {
		return NlSocketDropMembership(self.sock, int(group))
	}
	return nil
}

func (self *GenlHub) sync() error {
	var active []uint32
	for gkey, _ := range self.multicast {
		for _, ginfo := range self.groupIds {
			if ginfo.Family == gkey.Family && ginfo.Name == gkey.Name {
				active = append(active, ginfo.Id)
			}
		}
	}
	for _, old := range self.membership {
		drop := true
		for _, new := range active {
			if new == old {
				drop = false
			}
		}
		if drop {
			if err := self.leave(old); err != nil {
				return err
			}
		}
	}
	for _, new := range active {
		join := true
		for _, old := range self.membership {
			if new == old {
				join = false
			}
		}
		if join {
			if err := self.join(new); err != nil {
				return err
			}
		}
	}
	return nil
}

func NewGenlHub() (*GenlHub, error) {
	self := &GenlHub{
		sock: NlSocketAlloc(),
		lock: &sync.Mutex{},
		familyIds: map[uint16]GenlFamily{
			GENL_ID_CTRL: GenlFamily{
				Id:      GENL_ID_CTRL,
				Name:    "nlctrl",
				Version: 1,
			},
		},
		groupIds: map[uint32]GenlGroup{
			GENL_ID_CTRL: GenlGroup{
				Id:     GENL_ID_CTRL,
				Family: "nlctrl",
				Name:   "notify",
			},
		},
		unicast:   make(map[uint32]chan GenlMessage),
		multicast: make(map[groupKey][]GenlListener),
	}
	if err := NlConnect(self.sock, syscall.NETLINK_GENERIC); err != nil {
		NlSocketFree(self.sock)
		return nil, err
	}
	go func() {
		feed := func(msg GenlMessage) {
			seq := msg.Header.Seq
			if seq == 0 { // multicast
				var listeners []GenlListener
				self.lock.Lock()
				if family, ok := self.familyIds[msg.Header.Type]; ok {
					for gkey, ls := range self.multicast {
						if gkey.Family == family.Name {
							for _, listener := range ls {
								if ok := func() bool { // remove duplicate
									for _, li := range listeners {
										if li == listener {
											return false
										}
									}
									return true
								}(); ok {
									listeners = append(listeners, listener)
								}
							}
						}
					}
				} else {
					log.Print("got unknown family message")
				}
				self.lock.Unlock()

				for _, listener := range listeners {
					listener.GenlListen(msg)
				}
			} else {
				self.lock.Lock()
				listener := self.unicast[seq]
				self.lock.Unlock()

				if listener != nil {
					listener <- msg
					mtype := msg.Header.Type
					if mtype == syscall.NLMSG_DONE || mtype == syscall.NLMSG_ERROR { // NlSock.Flags NL_NO_AUTO_ACK is 0 by default
						self.lock.Lock()
						delete(self.unicast, seq)
						self.lock.Unlock()

						close(listener)
					}
				}
			}
		}
		for {
			buf := make([]byte, syscall.Getpagesize())
			if bufN, _, err := syscall.Recvfrom(self.sock.Fd, buf, syscall.MSG_TRUNC); err != nil {
				if e, ok := err.(syscall.Errno); ok && e.Temporary() {
					continue
				}
				feed(GenlMessage{Error: err})
				return
			} else if bufN > len(buf) {
				feed(GenlMessage{Error: fmt.Errorf("msg trunc")})
				return
			} else if msgs, err := syscall.ParseNetlinkMessage(buf[:bufN]); err != nil {
				feed(GenlMessage{Error: err})
				return
			} else {
				for _, msg := range msgs {
					switch msg.Header.Type {
					default:
						feed(GenlMessage{
							Header:  msg.Header,
							Family:  self.familyIds[msg.Header.Type].Name,
							Genl:    (*GenlMsghdr)(unsafe.Pointer(&msg.Data[0])),
							Payload: msg.Data[GENL_HDRLEN:],
						})
					case syscall.NLMSG_ERROR:
						err := *(*syscall.NlMsgerr)(unsafe.Pointer(&msg.Data[0]))
						feed(GenlMessage{
							Header: msg.Header,
							Error:  MsgError{In: err},
						})
					case syscall.NLMSG_DONE:
						feed(GenlMessage{
							Header:  msg.Header,
							Genl:    nil,
							Payload: msg.Data,
						})
					}
				}
			}
		}
	}()

	self.Add("nlctrl", "notify", self)
	if res, err := self.Request("nlctrl", CTRL_VERSION, CTRL_CMD_GETFAMILY, syscall.NLM_F_DUMP, nil, nil); err != nil {
		return nil, err
	} else {
		for _, r := range res {
			self.GenlListen(r)
		}
	}
	return self, nil
}

func (self GenlHub) Close() {
	NlSocketFree(self.sock)
}

func (self GenlHub) GenlListen(msg GenlMessage) {
	if msg.Header.Type != GENL_ID_CTRL {
		return
	}
	family := GenlFamily{}
	groups := make(map[uint32]GenlGroup)
	if attrs, err := CtrlPolicy.Parse(msg.Payload); err != nil {
		log.Print(err)
	} else {
		family.FromAttrs(attrs)

		familyName := func() string {
			self.lock.Lock()
			defer self.lock.Unlock()
			if f, ok := self.familyIds[family.Id]; ok {
				return f.Name
			}
			return family.Name
		}
		if grps := attrs.Get(CTRL_ATTR_MCAST_GROUPS); grps != nil {
			for _, grp := range []Attr(grps.(AttrList)) {
				gattr := grp.Value.(AttrList)
				key := gattr.Get(CTRL_ATTR_MCAST_GRP_ID).(uint32)
				groups[key] = GenlGroup{
					Id:     key,
					Family: familyName,
					Name:   NlaStringRemoveNul(gattr.Get(CTRL_ATTR_MCAST_GRP_NAME).(string)),
				}
			}
		}
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	switch msg.Genl.Cmd {
	case CTRL_CMD_NEWFAMILY:
		self.familyIds[family.Id] = family
		fallthrough
	case CTRL_CMD_NEWMCAST_GRP:
		for _, grp := range groups {
			if _, exists := self.groupIds[grp.Id]; !exists {
				self.groupIds[grp.Id] = grp
			}
		}
	case CTRL_CMD_DELFAMILY:
		delete(self.familyIds, family.Id)
		fallthrough
	case CTRL_CMD_DELMCAST_GRP:
		for _, grp := range groups {
			if _, exists := self.groupIds[grp.Id]; exists {
				delete(self.groupIds, grp.Id)
			}
		}
	}
	self.sync()
}

func (self GenlHub) Request(family string, version uint8, cmd uint8, flags uint16, payload []byte, attr AttrList) ([]GenlMessage, error) {
	var familyInfo GenlFamily
	familyInfoMiss := true
	self.lock.Lock()
	for _, f := range self.familyIds {
		if f.Name == family {
			familyInfo = f
			familyInfoMiss = false
		}
	}
	self.lock.Unlock()
	if familyInfoMiss {
		return nil, fmt.Errorf("family %s not found", family)
	}

	res := make(chan GenlMessage)

	msg := make([]byte, GENL_HDRLEN+NLMSG_ALIGN(int(familyInfo.Hdrsize)))
	*(*GenlMsghdr)(unsafe.Pointer(&msg[0])) = GenlMsghdr{
		Cmd:     cmd,
		Version: version,
	}
	copy(msg[GENL_HDRLEN:], payload)
	msg = append(msg, attr.Bytes()...)

	if err := func() error {
		self.lock.Lock()
		defer self.lock.Unlock()
		self.unicast[self.sock.SeqNext] = res
		if err := NlSendSimple(self.sock, familyInfo.Id, flags, msg); err != nil {
			return err
		}
		return nil
	}(); err != nil {
		return nil, err
	}

	var ret []GenlMessage
	for r := range res {
		ret = append(ret, r)
	}
	return ret, nil
}

// Add adds a GenlListener to GenlHub.
// listeners will recieve all of the same family events, regardless of their group registration.
// If you want to limited group multicast, create separate GenlHub for each.
func (self GenlHub) Add(family, group string, listener GenlListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	key := groupKey{Family: family, Name: group}
	self.multicast[key] = append(self.multicast[key], listener)
	return self.sync()
}

func (self GenlHub) Remove(family, group string, listener GenlListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	key := groupKey{Family: family, Name: group}
	var active []GenlListener
	for _, li := range self.multicast[key] {
		if li != listener {
			active = append(active, li)
		}
	}
	self.multicast[key] = active
	return self.sync()
}
