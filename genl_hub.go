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
	Genl    GenlMsghdr
	Payload []byte // fixe header + attributes
	Error   error
}

type GenlListener interface {
	GenlListen(GenlMessage)
}

type groupKey struct {
	Family string
	Group  string
}

type GenlHub struct {
	Sock      *NlSock
	Lock      *sync.Mutex
	Unicast   map[uint32]chan GenlMessage
	Multicast map[groupKey][]GenlListener
}

var genlRegistry = genlRegistryWatcher{
	Lock: &sync.Mutex{},
	Family: map[uint16]GenlFamily{
		GENL_ID_CTRL: GenlFamily{
			Id:      GENL_ID_CTRL,
			Name:    "nlctl",
			Version: 1,
		},
	},
	Group: make(map[uint32]GenlGroup),
}

type genlRegistryWatcher struct {
	Lock   *sync.Mutex
	Family map[uint16]GenlFamily
	Group  map[uint32]GenlGroup
}

func init() {
	if hub, err := NewGenlHub(); err != nil {
		panic(err)
	} else {
		hub.Add("nlctl", "notify", genlRegistry)
		if res, err := hub.Request("nlctl", CTRL_CMD_GETFAMILY, syscall.NLM_F_DUMP, nil, nil); err != nil {
			panic(err)
		} else {
			for msg := range res {
				genlRegistry.GenlListen(msg)
			}
		}
	}
}

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
				genlRegistry.Lock.Lock()
				defer genlRegistry.Lock.Unlock()

				switch msg.Genl.Cmd {
				case CTRL_CMD_NEWFAMILY:
					genlRegistry.Family[family.Id] = family
					for pid, grp := range groups {
						grp.Family = family.Name
						genlRegistry.Group[pid] = grp
					}
				case CTRL_CMD_NEWMCAST_GRP:
					familyName := family.Name
					if rfamily, ok := genlRegistry.Family[family.Id]; ok {
						familyName = rfamily.Name
					}
					for pid, grp := range groups {
						grp.Family = familyName
						genlRegistry.Group[pid] = grp
					}
				case CTRL_CMD_DELFAMILY:
					if rfamily, ok := genlRegistry.Family[family.Id]; ok {
						delete(genlRegistry.Family, family.Id)

						var gids []uint32
						for gid, grp := range genlRegistry.Group {
							if grp.Name == rfamily.Name {
								gids = append(gids, gid)
							}
						}
						for _, gid := range gids {
							delete(genlRegistry.Group, gid)
						}
					}
				case CTRL_CMD_DELMCAST_GRP:
					for pid, _ := range groups {
						delete(genlRegistry.Group, pid)
					}
				}
			}()
		}
	}
}

func genlFamilyAtoi(family string) *GenlFamily {
	genlRegistry.Lock.Lock()
	defer genlRegistry.Lock.Unlock()

	for _, f := range genlRegistry.Family {
		if f.Name == family {
			return &f
		}
	}
	return nil
}

func genlGroupAtoi(family, name string) *GenlGroup {
	genlRegistry.Lock.Lock()
	defer genlRegistry.Lock.Unlock()

	for _, grp := range genlRegistry.Group {
		if grp.Family == family && grp.Name == name {
			return &grp
		}
	}
	return nil
}

func genlGroupItoa(pid uint32) *GenlGroup {
	genlRegistry.Lock.Lock()
	defer genlRegistry.Lock.Unlock()

	for _, grp := range genlRegistry.Group {
		if grp.Id == pid {
			return &grp
		}
	}
	return nil
}

func NewGenlHub() (GenlHub, error) {
	self := GenlHub{
		Sock:      NlSocketAlloc(),
		Lock:      &sync.Mutex{},
		Unicast:   make(map[uint32]chan GenlMessage),
		Multicast: make(map[groupKey][]GenlListener),
	}
	if err := NlConnect(self.Sock, syscall.NETLINK_GENERIC); err != nil {
		return self, err
	}
	go func() {
		feed := func(msg GenlMessage) {
			seq := msg.Header.Seq
			if seq == 0 {
				if grp := genlGroupItoa(msg.Header.Pid); grp != nil {
					self.Lock.Lock()
					listeners := self.Multicast[groupKey{Family: grp.Family, Group: grp.Name}]
					self.Lock.Unlock()

					for _, listener := range listeners {
						listener.GenlListen(msg)
					}
				}
			} else {
				self.Lock.Lock()
				listener := self.Unicast[seq]
				self.Lock.Unlock()

				if listener != nil {
					listener <- msg
					mtype := msg.Header.Type
					if mtype == syscall.NLMSG_DONE || mtype == syscall.NLMSG_ERROR {
						self.Lock.Lock()
						delete(self.Unicast, seq)
						self.Lock.Unlock()

						close(listener)
					}
				}
			}
		}
		for {
			buf := make([]byte, syscall.Getpagesize())
			if bufN, _, err := syscall.Recvfrom(self.Sock.Fd, buf, syscall.MSG_TRUNC); err != nil {
				feed(GenlMessage{Error: err})
			} else if bufN > len(buf) {
				feed(GenlMessage{Error: fmt.Errorf("msg trunc")})
			} else if msgs, err := syscall.ParseNetlinkMessage(buf[:bufN]); err != nil {
				feed(GenlMessage{Error: err})
			} else {
				for _, msg := range msgs {
					feed(GenlMessage{
						Header:  msg.Header,
						Genl:    *(*GenlMsghdr)(unsafe.Pointer(&msg.Data[0])),
						Payload: msg.Data[GENL_HDRLEN:],
					})
				}
			}
		}
	}()
	return self, nil
}

func (self GenlHub) Request(family string, cmd uint8, flags uint16, payload []byte, attr AttrList) (chan GenlMessage, error) {
	res := make(chan GenlMessage)

	familyInfo := genlFamilyAtoi(family)
	if familyInfo == nil {
		close(res)
		return res, fmt.Errorf("family not found")
	}

	msg := make([]byte, GENL_HDRLEN+NLMSG_ALIGN(int(familyInfo.Hdrsize)))
	*(*GenlMsghdr)(unsafe.Pointer(&msg[0])) = GenlMsghdr{
		Cmd:     cmd,
		Version: uint8(familyInfo.Version),
	}
	copy(msg[GENL_HDRLEN:], payload)
	msg = append(msg, attr.Bytes()...)

	self.Lock.Lock()
	defer self.Lock.Unlock()
	self.Unicast[self.Sock.SeqNext] = res
	return res, NlSendSimple(self.Sock, familyInfo.Id, flags, msg)
}

func (self GenlHub) Add(family, group string, listener GenlListener) error {
	self.Lock.Lock()
	defer self.Lock.Unlock()

	groupInfo := genlGroupAtoi(family, group)
	if groupInfo == nil {
		return fmt.Errorf("group not found")
	}

	key := groupKey{
		Family: family,
		Group:  group,
	}
	if len(self.Multicast[key]) == 0 {
		if err := NlSocketAddMembership(self.Sock, int(groupInfo.Id)); err != nil {
			return err
		}
	}
	self.Multicast[key] = append(self.Multicast[key], listener)
	return nil
}

func (self GenlHub) Remove(family, group string, listener GenlListener) error {
	self.Lock.Lock()
	defer self.Lock.Unlock()

	key := groupKey{
		Family: family,
		Group:  group,
	}
	var active []GenlListener
	for _, li := range self.Multicast[key] {
		if li != listener {
			active = append(active, li)
		}
	}
	self.Multicast[key] = active

	if len(active) == 0 {
		if groupInfo := genlGroupAtoi(family, group); groupInfo == nil {
			return fmt.Errorf("group not found")
		} else if err := NlSocketDropMembership(self.Sock, int(groupInfo.Id)); err != nil {
			return err
		}
	}
	return nil
}

func C() {
	log.Print(genlRegistry)
}
