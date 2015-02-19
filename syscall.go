package nlgo

import (
	"unsafe"
)

const SOL_NETLINK = 0x10e // 270

type Ndmsg struct {
	Family  uint8
	_       uint8
	_       uint16
	Ifindex uint32
	State   uint16
	Flags   uint8
	Type    uint8
}

const SizeofNdmsg = 12

type Tcmsg struct {
	Family  uint8
	_       uint8
	_       uint16
	Ifindex int
	Handle  uint32
	Parent  uint32
	Info    uint32
}

var SizeofTcmsg int = int(unsafe.Sizeof(Tcmsg{}))
