// rtlink provides RTM_*LINK util

package rtlink

import (
	"fmt"
	"github.com/hkwi/nlgo"
	"syscall"
	"unsafe"
)

func GetByName(hub *nlgo.RtHub, name string) (syscall.IfInfomsg, error) {
	var ret syscall.IfInfomsg
	if msgs, err := hub.Request(
		syscall.RTM_GETLINK,
		syscall.NLM_F_REQUEST,
		nil,
		nlgo.AttrSlice{
			nlgo.Attr{
				Header: syscall.NlAttr{
					Type: syscall.IFLA_IFNAME,
				},
				Value: nlgo.NulString(name),
			},
		},
	); err != nil {
		return ret, err
	} else {
		for _, msg := range msgs {
			if msg.Error != nil {
				continue
			}
			switch msg.Message.Header.Type {
			case syscall.RTM_NEWLINK:
				if attrs, err := nlgo.RouteLinkPolicy.Parse(msg.Message.Data[nlgo.NLMSG_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
					continue
				} else if string(attrs.(nlgo.AttrMap).Get(syscall.IFLA_IFNAME).(nlgo.NulString)) == name {
					return *(*syscall.IfInfomsg)(unsafe.Pointer(&msg.Message.Data[0])), nil
				}
			}
		}
	}
	return ret, fmt.Errorf("response empty")
}

func GetNameByIndex(hub *nlgo.RtHub, index int) (string, error) {
	if msgs, err := hub.Request(
		syscall.RTM_GETLINK,
		syscall.NLM_F_REQUEST,
		(*[syscall.SizeofIfInfomsg]byte)(unsafe.Pointer(&syscall.IfInfomsg{
			Index: int32(index),
		}))[:],
		nil,
	); err != nil {
		return "", err
	} else {
		for _, msg := range msgs {
			if msg.Error != nil {
				continue
			}
			switch msg.Message.Header.Type {
			case syscall.RTM_NEWLINK:
				if (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Message.Data[0])).Index == int32(index) {
					if attrs, err := nlgo.RouteLinkPolicy.Parse(msg.Message.Data[nlgo.NLMSG_ALIGN(syscall.SizeofIfInfomsg):]); err != nil {
						return "", err
					} else {
						return string(attrs.(nlgo.AttrMap).Get(syscall.IFLA_IFNAME).(nlgo.NulString)), nil
					}
				}
			}
		}
		return "", fmt.Errorf("response empty")
	}
}
