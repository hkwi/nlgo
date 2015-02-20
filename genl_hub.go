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
	Payload []byte // fixe header + attributes
	Error   error
}

type GenlListener interface {
	GenlListen(GenlMessage)
}

func groupKey(family, group string) string {
	return NlaStringRemoveNul(family) + "\x00" + NlaStringRemoveNul(group)
}

type GenlHub struct {
	sock      *NlSock
	lock      *sync.Mutex
	unicast   map[uint32]chan GenlMessage
	multicast map[string][]GenlListener
}

func (self GenlHub) Close() {
	NlSocketFree(self.sock)
}

type genlRegistryWatcher struct {
	lock   *sync.Mutex
	family map[uint16]GenlFamily
	group  map[uint32]GenlGroup
}

var genlRegistry = genlRegistryWatcher{
	lock: &sync.Mutex{},
	family: map[uint16]GenlFamily{
		GENL_ID_CTRL: GenlFamily{
			Id:      GENL_ID_CTRL,
			Name:    "nlctrl",
			Version: 1,
		},
	},
	group: make(map[uint32]GenlGroup),
}

var genlRegistryHub *GenlHub

func (self genlRegistryWatcher) GenlListen(msg GenlMessage) {
	if msg.Header.Type == GENL_ID_CTRL {
		if attrs, err := CtrlPolicy.Parse(msg.Payload); err != nil {
			log.Print(err)
		} else {
			family := GenlFamily{}
			family.FromAttrs(attrs)

			groups := make(map[uint32]GenlGroup)
			if grps := attrs.Get(CTRL_ATTR_MCAST_GROUPS); grps != nil {
				for _, grp := range []Attr(grps.(AttrList)) {
					gattr := grp.Value.(AttrList)
					key := gattr.Get(CTRL_ATTR_MCAST_GRP_ID).(uint32)
					groups[key] = GenlGroup{
						Id:   key,
						Name: NlaStringRemoveNul(gattr.Get(CTRL_ATTR_MCAST_GRP_NAME).(string)),
					}
				}
			}

			func() {
				genlRegistry.lock.Lock()
				defer genlRegistry.lock.Unlock()

				switch msg.Genl.Cmd {
				case CTRL_CMD_NEWFAMILY:
					genlRegistry.family[family.Id] = family
					for pid, grp := range groups {
						grp.Family = family.Name
						genlRegistry.group[pid] = grp
					}
				case CTRL_CMD_NEWMCAST_GRP:
					familyName := family.Name
					if rfamily, ok := genlRegistry.family[family.Id]; ok {
						familyName = rfamily.Name
					}
					for pid, grp := range groups {
						grp.Family = familyName
						genlRegistry.group[pid] = grp
					}
				case CTRL_CMD_DELFAMILY:
					if rfamily, ok := genlRegistry.family[family.Id]; ok {
						delete(genlRegistry.family, family.Id)

						var gids []uint32
						for gid, grp := range genlRegistry.group {
							if grp.Name == rfamily.Name {
								gids = append(gids, gid)
							}
						}
						for _, gid := range gids {
							delete(genlRegistry.group, gid)
						}
					}
				case CTRL_CMD_DELMCAST_GRP:
					for pid, _ := range groups {
						delete(genlRegistry.group, pid)
					}
				}
			}()
		}
	}
}

func genlFamilyAtoi(family string) *GenlFamily {
	if genlRegistryHub != nil {
		genlRegistry.lock.Lock()
		defer genlRegistry.lock.Unlock()

		for _, f := range genlRegistry.family {
			if f.Name == family {
				return &f
			}
		}
	} else if hub, err := NewGenlHub(); err == nil {
		defer hub.Close()

		if res, err := hub.Request("nlctrl", CTRL_CMD_GETFAMILY, syscall.NLM_F_DUMP, nil, AttrList{Attr{
			Header: syscall.NlAttr{
				Type: CTRL_ATTR_FAMILY_NAME,
			},
			Value: family,
		}}); err != nil {
			for _, r := range res {
				if r.Genl != nil && r.Genl.Cmd == CTRL_CMD_NEWFAMILY {
					if attrs, err := CtrlPolicy.Parse(r.Payload); err == nil {
						if NlaStringEquals(attrs.Get(CTRL_ATTR_FAMILY_NAME).(string), family) {
							genlFamily := &GenlFamily{}
							genlFamily.FromAttrs(attrs)
							return genlFamily
						}
					}
				}
			}
		}
	}
	return nil
}

func genlGroupAtoi(family, name string) *GenlGroup {
	if genlRegistryHub != nil {
		genlRegistry.lock.Lock()
		defer genlRegistry.lock.Unlock()

		for _, grp := range genlRegistry.group {
			if grp.Family == family && grp.Name == name {
				return &grp
			}
		}
	} else if hub, err := NewGenlHub(); err == nil {
		defer hub.Close()

		if res, err := hub.Request("nlctrl", CTRL_CMD_GETFAMILY, syscall.NLM_F_DUMP, nil, AttrList{Attr{
			Header: syscall.NlAttr{
				Type: CTRL_ATTR_FAMILY_NAME,
			},
			Value: family,
		}}); err != nil {
			for _, r := range res {
				if r.Genl != nil && r.Genl.Cmd == CTRL_CMD_NEWFAMILY {
					if attrs, err := CtrlPolicy.Parse(r.Payload); err == nil {
						if NlaStringEquals(attrs.Get(CTRL_ATTR_FAMILY_NAME).(string), family) {
							for _, attr := range []Attr(attrs.Get(CTRL_ATTR_MCAST_GROUPS).(AttrList)) {
								gattr := attr.Value.(AttrList)
								if NlaStringEquals(gattr.Get(CTRL_ATTR_MCAST_GRP_NAME).(string), name) {
									return &GenlGroup{
										Id:     gattr.Get(CTRL_ATTR_MCAST_GRP_ID).(uint32),
										Family: family,
										Name:   name,
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func genlGroupItoa(pid uint32) *GenlGroup {
	if genlRegistryHub != nil {
		genlRegistry.lock.Lock()
		defer genlRegistry.lock.Unlock()

		for _, grp := range genlRegistry.group {
			if grp.Id == pid {
				return &grp
			}
		}
	} else if hub, err := NewGenlHub(); err == nil {
		defer hub.Close()

		if res, err := hub.Request("nlctrl", CTRL_CMD_GETFAMILY, syscall.NLM_F_DUMP, nil, nil); err != nil {
			for _, r := range res {
				if r.Genl != nil && r.Genl.Cmd == CTRL_CMD_NEWFAMILY {
					if attrs, err := CtrlPolicy.Parse(r.Payload); err == nil {
						for _, attr := range []Attr(attrs.Get(CTRL_ATTR_MCAST_GROUPS).(AttrList)) {
							gattr := attr.Value.(AttrList)
							if gattr.Get(CTRL_ATTR_MCAST_GRP_ID).(uint32) == pid {
								return &GenlGroup{
									Id:     gattr.Get(CTRL_ATTR_MCAST_GRP_ID).(uint32),
									Family: NlaStringRemoveNul(attrs.Get(CTRL_ATTR_FAMILY_NAME).(string)),
									Name:   NlaStringRemoveNul(gattr.Get(CTRL_ATTR_MCAST_GRP_NAME).(string)),
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func DefaultGenlHub() (*GenlHub, error) {
	if genlRegistryHub == nil {
		if hub, err := NewGenlHub(); err != nil {
			return nil, err
		} else {
			genlRegistryHub = hub
		}
	}
	genlRegistryHub.Add("nlctrl", "notify", genlRegistry)
	if res, err := genlRegistryHub.Request("nlctrl", CTRL_CMD_GETFAMILY, syscall.NLM_F_DUMP, nil, nil); err != nil {
		return nil, err
	} else {
		for _, msg := range res {
			genlRegistry.GenlListen(msg)
		}
	}
	return genlRegistryHub, nil
}

func NewGenlHub() (*GenlHub, error) {
	self := &GenlHub{
		sock:      NlSocketAlloc(),
		lock:      &sync.Mutex{},
		unicast:   make(map[uint32]chan GenlMessage),
		multicast: make(map[string][]GenlListener),
	}
	if err := NlConnect(self.sock, syscall.NETLINK_GENERIC); err != nil {
		NlSocketFree(self.sock)
		return nil, err
	}
	go func() {
		feed := func(msg GenlMessage) {
			seq := msg.Header.Seq
			if seq == 0 {
				if grp := genlGroupItoa(msg.Header.Pid); grp != nil {
					self.lock.Lock()
					listeners := self.multicast[groupKey(grp.Family, grp.Name)]
					self.lock.Unlock()

					for _, listener := range listeners {
						listener.GenlListen(msg)
					}
				}
			} else {
				self.lock.Lock()
				listener := self.unicast[seq]
				self.lock.Unlock()

				if listener != nil {
					listener <- msg
					mtype := msg.Header.Type
					if mtype == syscall.NLMSG_DONE || mtype == syscall.NLMSG_ERROR { // NlSock.Flags NL_NO_AUTO_ACK is 0
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
				feed(GenlMessage{Error: err})
			} else if bufN > len(buf) {
				feed(GenlMessage{Error: fmt.Errorf("msg trunc")})
			} else if msgs, err := syscall.ParseNetlinkMessage(buf[:bufN]); err != nil {
				feed(GenlMessage{Error: err})
			} else {
				for _, msg := range msgs {
					switch msg.Header.Type {
					default:
						feed(GenlMessage{
							Header:  msg.Header,
							Genl:    (*GenlMsghdr)(unsafe.Pointer(&msg.Data[0])),
							Payload: msg.Data[GENL_HDRLEN:],
						})
					case syscall.NLMSG_ERROR, syscall.NLMSG_DONE:
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
	return self, nil
}

func (self GenlHub) Request(family string, cmd uint8, flags uint16, payload []byte, attr AttrList) ([]GenlMessage, error) {
	familyInfo := genlFamilyAtoi(family)
	if familyInfo == nil {
		return nil, fmt.Errorf("family not found")
	}

	res := make(chan GenlMessage)

	msg := make([]byte, GENL_HDRLEN+NLMSG_ALIGN(int(familyInfo.Hdrsize)))
	*(*GenlMsghdr)(unsafe.Pointer(&msg[0])) = GenlMsghdr{
		Cmd:     cmd,
		Version: uint8(familyInfo.Version),
	}
	copy(msg[GENL_HDRLEN:], payload)
	msg = append(msg, attr.Bytes()...)

	self.lock.Lock()
	self.unicast[self.sock.SeqNext] = res
	self.lock.Unlock()

	if err := NlSendSimple(self.sock, familyInfo.Id, flags, msg); err != nil {
		return nil, err
	}

	var ret []GenlMessage
	for r := range res {
		ret = append(ret, r)
	}
	return ret, nil
}

func (self GenlHub) Add(family, group string, listener GenlListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	groupInfo := genlGroupAtoi(family, group)
	if groupInfo == nil {
		return fmt.Errorf("group not found")
	}

	key := groupKey(family, group)
	if len(self.multicast[key]) == 0 {
		if err := NlSocketAddMembership(self.sock, int(groupInfo.Id)); err != nil {
			return err
		}
	}
	self.multicast[key] = append(self.multicast[key], listener)
	return nil
}

func (self GenlHub) Remove(family, group string, listener GenlListener) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	key := groupKey(family, group)
	var active []GenlListener
	for _, li := range self.multicast[key] {
		if li != listener {
			active = append(active, li)
		}
	}
	self.multicast[key] = active

	if len(active) == 0 {
		if groupInfo := genlGroupAtoi(family, group); groupInfo == nil {
			return fmt.Errorf("group not found")
		} else if err := NlSocketDropMembership(self.sock, int(groupInfo.Id)); err != nil {
			return err
		}
	}
	return nil
}
