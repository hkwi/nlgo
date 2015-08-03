// +build linux

package nlgo

import (
	"fmt"
	"syscall"
	"unsafe"
)

/*
Genl socket message is classified by GenlFamily.
One genl socket can handle multiple GenlFamily messages.
There's a predefined GenlFamily, "nlctrl" which has one "notify" group.
The other GenlFamily can be registered dynamically in the kernel.
By sending nlctrl family message, we can query those GenlFamily information.
*/

func GenlCtrlResolve(sk *NlSock, name string) (uint16, error) {
	if attrs, err := GenlCtrlProbeByName(sk, name); err != nil {
		return 0, err
	} else {
		if v := attrs.Get(CTRL_ATTR_FAMILY_ID); v != nil {
			return uint16(v.(U16)), nil
		} else {
			return 0, fmt.Errorf("resposne attribute error")
		}
	}
}

func GenlCtrlGrpByName(sk *NlSock, family, group string) (uint32, error) {
	if attrs, err := GenlCtrlProbeByName(sk, family); err != nil {
		return 0, err
	} else {
		if grps := attrs.Get(CTRL_ATTR_MCAST_GROUPS); grps != nil {
			for _, grpc := range grps.(AttrSlice).Slice() {
				grp := grpc.Value.(AttrMap)
				if string(grp.Get(CTRL_ATTR_MCAST_GRP_NAME).(String)) == group {
					return uint32(grp.Get(CTRL_ATTR_MCAST_GRP_ID).(U32)), nil
				}
			}
		}
		return 0, fmt.Errorf("resposne attribute error")
	}
}

// genl_ctrl_probe_by_name is not exposed in the original libnl
func GenlCtrlProbeByName(sk *NlSock, name string) (AttrMap, error) {
	if err := GenlSendSimple(sk, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_VERSION, syscall.NLM_F_DUMP); err != nil {
		return AttrMap{}, err
	}
	var ret AttrMap
	err := func() error {
		for {
			buf := make([]byte, syscall.Getpagesize())
			if nn, _, err := syscall.Recvfrom(sk.Fd, buf, syscall.MSG_TRUNC); err != nil {
				return err
			} else if nn > len(buf) {
				return NLE_MSG_TRUNC
			} else {
				buf = buf[:nn]
			}
			if msgs, err := syscall.ParseNetlinkMessage(buf); err != nil {
				return err
			} else {
				for _, msg := range msgs {
					switch msg.Header.Type {
					case GENL_ID_CTRL:
						genl := (*GenlMsghdr)(unsafe.Pointer(&msg.Data[0]))
						switch genl.Cmd {
						case CTRL_CMD_NEWFAMILY:
							if attrs, err := CtrlPolicy.Parse(msg.Data[GENL_HDRLEN:]); err != nil {
								return err
							} else if info, ok := attrs.(AttrMap); !ok {
								// shold not happen
							} else if value := info.Get(CTRL_ATTR_FAMILY_NAME); value == nil {
								// should not happen by kernel
							} else if string(value.(String)) == name {
								ret = info
							}
						default:
							return fmt.Errorf("unexpected command")
						}
					case syscall.NLMSG_DONE:
						return nil
					case syscall.NLMSG_ERROR:
						return fmt.Errorf("NlMsgerr=%s", (*syscall.NlMsgerr)(unsafe.Pointer(&msg.Data[0])))
					default:
						return fmt.Errorf("unexpected NlMsghdr=%s", msg.Header)
					}
				}
			}
		}
	}()
	return ret, err
}

type GenlFamily struct {
	Id      uint16
	Name    string
	Version uint32
	Hdrsize uint32
}

func (self *GenlFamily) FromAttrs(attrs AttrMap) {
	if t := attrs.Get(CTRL_ATTR_FAMILY_ID); t != nil {
		self.Id = uint16(t.(U16))
	}
	if t := attrs.Get(CTRL_ATTR_FAMILY_NAME); t != nil {
		self.Name = string(t.(NulString))
	}
	if t := attrs.Get(CTRL_ATTR_VERSION); t != nil {
		self.Version = uint32(t.(U32))
	}
	if t := attrs.Get(CTRL_ATTR_HDRSIZE); t != nil {
		self.Hdrsize = uint32(t.(U32))
	}
}

type GenlGroup struct {
	Id     uint32
	Family string
	Name   string
}
