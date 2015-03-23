// +build linux

package nlgo

import (
	"fmt"
	"syscall"
	"unsafe"
)

func GenlCtrlResolve(sk *NlSock, name string) (uint16, error) {
	if attrs, err := GenlCtrlProbeByName(sk, name); err != nil {
		return 0, err
	} else {
		if v := attrs.Get(CTRL_ATTR_FAMILY_ID); v != nil {
			return v.(uint16), nil
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
			for _, grpc := range []Attr(grps.(AttrList)) {
				grp := grpc.Value.(AttrList)
				if gname := grp.Get(CTRL_ATTR_MCAST_GRP_NAME); gname != nil && NlaStringEquals(gname.(string), group) {
					return grp.Get(CTRL_ATTR_MCAST_GRP_ID).(uint32), nil
				}
			}
		}
		return 0, fmt.Errorf("resposne attribute error")
	}
}

// genl_ctrl_probe_by_name is not exposed in the original libnl
func GenlCtrlProbeByName(sk *NlSock, name string) (AttrList, error) {
	if err := GenlSendSimple(sk, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_VERSION, syscall.NLM_F_DUMP); err != nil {
		return nil, err
	}
	var ret AttrList
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
							} else {
								if v := attrs.Get(CTRL_ATTR_FAMILY_NAME); v != nil && NlaStringEquals(v.(string), name) {
									ret = attrs
								}
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

func (self *GenlFamily) FromAttrs(attrs AttrList) {
	if t := attrs.Get(CTRL_ATTR_FAMILY_ID); t != nil {
		self.Id = t.(uint16)
	}
	if t := attrs.Get(CTRL_ATTR_FAMILY_NAME); t != nil {
		self.Name = NlaStringRemoveNul(t.(string))
	}
	if t := attrs.Get(CTRL_ATTR_VERSION); t != nil {
		self.Version = t.(uint32)
	}
	if t := attrs.Get(CTRL_ATTR_HDRSIZE); t != nil {
		self.Hdrsize = t.(uint32)
	}
}

type GenlGroup struct {
	Id     uint32
	Family string
	Name   string
}
