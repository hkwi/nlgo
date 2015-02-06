package nlgo

import (
	"syscall"
	"unsafe"
)

type GenlMsghdr struct {
	Cmd     uint8
	Version uint8
	_       uint16
}

const SizeofGenlMsghdr = 0x04

var GENL_HDRLEN int = NLMSG_ALIGN(SizeofGenlMsghdr)

const (
	GENL_ADMIN_PERM = 1 << iota
	GENL_CMD_CAP_DO
	GENL_CMD_CAP_DUMP
	GENL_CMD_CAP_HASPOL
)

func GenlConnect(sk *NlSock) error {
	return NlConnect(sk, syscall.NETLINK_GENERIC)
}

func GenlSendSimple(sk *NlSock, family uint16, cmd, version uint8, flags uint16) error {
	hdr := (*[SizeofGenlMsghdr]byte)(unsafe.Pointer(&GenlMsghdr{
		Cmd:     cmd,
		Version: version,
	}))
	return NlSendSimple(sk, family, flags, hdr[:])
}

const (
	GENL_ID_GENERATE = 0
	GENL_ID_CTRL     = 0x10
)

const CTRL_VERSION = 0x0001

const (
	CTRL_CMD_UNSPEC = iota
	CTRL_CMD_NEWFAMILY
	CTRL_CMD_DELFAMILY
	CTRL_CMD_GETFAMILY
	CTRL_CMD_NEWOPS
	CTRL_CMD_DELOPS
	CTRL_CMD_GETOPS
	CTRL_CMD_NEWMCAST_GRP
	CTRL_CMD_DELMCAST_GRP
	CTRL_CMD_GETMCAST_GRP
)

// CTRL

const (
	CTRL_ATTR_UNSPEC = iota
	CTRL_ATTR_FAMILY_ID
	CTRL_ATTR_FAMILY_NAME
	CTRL_ATTR_VERSION
	CTRL_ATTR_HDRSIZE
	CTRL_ATTR_MAXATTR
	CTRL_ATTR_OPS
	CTRL_ATTR_MCAST_GROUPS
)

const (
	CTRL_ATTR_OP_UNSPEC = iota
	CTRL_ATTR_OP_ID
	CTRL_ATTR_OP_FLAGS // GENL_CMD_CAP_DUMP, etc.,
)

const (
	CTRL_ATTR_MCAST_GRP_UNSPEC = iota
	CTRL_ATTR_MCAST_GRP_NAME
	CTRL_ATTR_MCAST_GRP_ID
)

var CtrlPolicy MapPolicy = MapPolicy{
	CTRL_ATTR_FAMILY_ID:   NLA_U16,
	CTRL_ATTR_FAMILY_NAME: NLA_STRING,
	CTRL_ATTR_VERSION:     NLA_U32,
	CTRL_ATTR_HDRSIZE:     NLA_U32,
	CTRL_ATTR_MAXATTR:     NLA_U32,
	CTRL_ATTR_OPS: ListPolicy{
		Nested: MapPolicy{
			CTRL_ATTR_OP_ID:    NLA_U32,
			CTRL_ATTR_OP_FLAGS: NLA_U32,
		},
	},
	CTRL_ATTR_MCAST_GROUPS: ListPolicy{
		Nested: MapPolicy{
			CTRL_ATTR_MCAST_GRP_NAME: NLA_STRING,
			CTRL_ATTR_MCAST_GRP_ID:   NLA_U32,
		},
	},
}

/*
type CtrlAttr struct {
	FamilyId uint16
	FamilyName string
	Version uint32
	Hdrsize uint32
	Maxattr uint32
	Ops []CtrlOp
	McastGroups []CtrlMcastGrp
}

type CtrlOp struct {
	Id uint32
	Flags uint32
}

type CtrlMcastGrp struct {
	Id uint32
	Name string
}

func (self *CtrlAttr) UnmarshalBinary(buf []byte) error {
	for len(buf) > syscall.SizeofNlAttr {
		hdr := (*syscall.NlAttr)(unsafe.Pointer(&buf[0]))
		switch hdr.Type & NLA_TYPE_MASK {
		case CTRL_ATTR_FAMILY_ID:
			self.FamilyId = *(*uint16)(unsafe.Pointer(&buf[NLA_HDRLEN]))
		case CTRL_ATTR_FAMILY_NAME:
			self.FamilyName = string(bytes.Split(buf[NLA_HDRLEN:hdr.Len], []byte{0})[0])
		case CTRL_ATTR_VERSION:
			self.Version = *(*uint32)(unsafe.Pointer(&buf[NLA_HDRLEN]))
		case CTRL_ATTR_HDRSIZE:
			self.Hdrsize = *(*uint32)(unsafe.Pointer(&buf[NLA_HDRLEN]))
		case CTRL_ATTR_MAXATTR:
			self.Maxattr = *(*uint32)(unsafe.Pointer(&buf[NLA_HDRLEN]))
		case CTRL_ATTR_OPS:
			listBuf := buf[NLA_HDRLEN:hdr.Len]
			for len(listBuf) > NLA_HDRLEN {
				element := CtrlOp{}
				listHead := (*syscall.NlAttr)(unsafe.Pointer(&listBuf[0]))
				elementBuf := listBuf[NLA_HDRLEN:listHead.Len]
				for len(elementBuf) > NLA_HDRLEN {
					elementHead := (*syscall.NlAttr)(unsafe.Pointer(&elementBuf[0]))
					switch elementHead.Type & NLA_TYPE_MASK {
					case CTRL_ATTR_OP_ID:
						element.Id = *(*uint32)(unsafe.Pointer(&elementBuf[NLA_HDRLEN]))
					case CTRL_ATTR_OP_FLAGS:
						element.Flags = *(*uint32)(unsafe.Pointer(&elementBuf[NLA_HDRLEN]))
					default:
						return fmt.Errorf("unknown CTRL_ATTR_OP_(%d)", elementHead.Type)
					}
					elementBuf = elementBuf[NLA_ALIGN(int(elementHead.Len)):]
				}
				self.Ops = append(self.Ops, element)
				listBuf = listBuf[NLA_ALIGN(int(listHead.Len)):]
			}
		case CTRL_ATTR_MCAST_GROUPS:
			listBuf := buf[NLA_HDRLEN:hdr.Len]
			for len(listBuf) > NLA_HDRLEN {
				element := CtrlMcastGrp{}
				listHead := (*syscall.NlAttr)(unsafe.Pointer(&listBuf[0]))
				elementBuf := listBuf[NLA_HDRLEN:listHead.Len]
				for len(elementBuf) > NLA_HDRLEN {
					elementHead := (*syscall.NlAttr)(unsafe.Pointer(&elementBuf[0]))
					switch elementHead.Type & NLA_TYPE_MASK {
					case CTRL_ATTR_MCAST_GRP_ID:
						element.Id = *(*uint32)(unsafe.Pointer(&elementBuf[NLA_HDRLEN]))
					case CTRL_ATTR_MCAST_GRP_NAME:
						element.Name = string(bytes.Split(elementBuf[NLA_HDRLEN:elementHead.Len], []byte{0})[0])
					default:
						return fmt.Errorf("unknown CTRL_ATTR_MCAST_GRP_(%d)", elementHead.Type)
					}
					elementBuf = elementBuf[NLA_ALIGN(int(elementHead.Len)):]
				}
				self.McastGroups = append(self.McastGroups, element)
				listBuf = listBuf[NLA_ALIGN(int(listHead.Len)):]
			}
		}
		buf = buf[NLA_ALIGN(int(hdr.Len)):]
	}
	return nil
}
*/
