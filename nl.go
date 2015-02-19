// Package nlgo implements netlink library routines.
//
// This was golang port of libnl. For basic concept, please have a look at
// original libnl documentation http://www.infradead.org/~tgr/libnl/ .
//
package nlgo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

func align(size, tick int) int {
	return (size + tick - 1) &^ (tick - 1)
}

func NLMSG_ALIGN(size int) int {
	return align(size, syscall.NLMSG_ALIGNTO)
}

func NLA_ALIGN(size int) int {
	return align(size, syscall.NLA_ALIGNTO)
}

var NLA_HDRLEN int = NLA_ALIGN(syscall.SizeofNlAttr)

// Attr represents single netlink attribute package.
// Developer memo: syscall.ParseNetlinkRouteAttr does not parse nested attributes.
// I wanted to make deep parser, and this is because Value is defined as interface{}.
type Attr struct {
	Header syscall.NlAttr
	Value  interface{}
}

func (self Attr) Field() uint16 {
	return self.Header.Type & NLA_TYPE_MASK
}

func (self Attr) Bytes() []byte {
	var length int
	var buf []byte
	self.Header.Type &= ^uint16(syscall.NLA_F_NESTED)
	switch SimplePolicy(self.Field()) {
	case NLA_U8:
		length = syscall.SizeofNlAttr + 1
		buf = make([]byte, NLA_ALIGN(length))
		buf[NLA_HDRLEN] = self.Value.(uint8)
	case NLA_S8:
		length = syscall.SizeofNlAttr + 1
		buf = make([]byte, NLA_ALIGN(length))
		buf[NLA_HDRLEN] = uint8(self.Value.(int8))
	case NLA_U16:
		length = syscall.SizeofNlAttr + 2
		buf = make([]byte, NLA_ALIGN(length))
		if self.Header.Type&syscall.NLA_F_NET_BYTEORDER == 0 {
			*(*uint16)(unsafe.Pointer(&buf[NLA_HDRLEN])) = self.Value.(uint16)
		} else {
			binary.BigEndian.PutUint16(buf[NLA_HDRLEN:], self.Value.(uint16))
		}
	case NLA_S16:
		length = syscall.SizeofNlAttr + 2
		buf = make([]byte, NLA_ALIGN(length))
		if self.Header.Type&syscall.NLA_F_NET_BYTEORDER == 0 {
			*(*int16)(unsafe.Pointer(&buf[NLA_HDRLEN])) = self.Value.(int16)
		} else {
			binary.BigEndian.PutUint16(buf[NLA_HDRLEN:], uint16(self.Value.(int16)))
		}
	case NLA_U32:
		length = syscall.SizeofNlAttr + 4
		buf = make([]byte, NLA_ALIGN(length))
		if self.Header.Type&syscall.NLA_F_NET_BYTEORDER == 0 {
			*(*uint32)(unsafe.Pointer(&buf[NLA_HDRLEN])) = self.Value.(uint32)
		} else {
			binary.BigEndian.PutUint32(buf[NLA_HDRLEN:], self.Value.(uint32))
		}
	case NLA_S32:
		length = syscall.SizeofNlAttr + 4
		buf = make([]byte, NLA_ALIGN(length))
		if self.Header.Type&syscall.NLA_F_NET_BYTEORDER == 0 {
			*(*int32)(unsafe.Pointer(&buf[NLA_HDRLEN])) = self.Value.(int32)
		} else {
			binary.BigEndian.PutUint32(buf[NLA_HDRLEN:], uint32(self.Value.(int32)))
		}
	case NLA_U64, NLA_MSECS:
		length = syscall.SizeofNlAttr + 8
		buf = make([]byte, NLA_ALIGN(length))
		if self.Header.Type&syscall.NLA_F_NET_BYTEORDER == 0 {
			*(*uint64)(unsafe.Pointer(&buf[NLA_HDRLEN])) = self.Value.(uint64)
		} else {
			binary.BigEndian.PutUint64(buf[NLA_HDRLEN:], self.Value.(uint64))
		}
	case NLA_S64:
		length = syscall.SizeofNlAttr + 8
		buf = make([]byte, NLA_ALIGN(length))
		if self.Header.Type&syscall.NLA_F_NET_BYTEORDER == 0 {
			*(*int64)(unsafe.Pointer(&buf[NLA_HDRLEN])) = self.Value.(int64)
		} else {
			binary.BigEndian.PutUint64(buf[NLA_HDRLEN:], uint64(self.Value.(int64)))
		}
	case NLA_STRING, NLA_NUL_STRING:
		vbytes := []byte(self.Value.(string))
		if vbytes[len(vbytes)-1] != 0 {
			vbytes = append(vbytes, 0) // NULL-termination
		}
		length = syscall.SizeofNlAttr + len(vbytes)
		buf = make([]byte, NLA_ALIGN(length))
		copy(buf[NLA_HDRLEN:], vbytes)
	case NLA_BINARY:
		vbytes := self.Value.([]byte)
		length = syscall.SizeofNlAttr + len(vbytes)
		buf = make([]byte, NLA_ALIGN(length))
		copy(buf[NLA_HDRLEN:], vbytes)
	case NLA_FLAG:
		length = syscall.SizeofNlAttr
		buf = make([]byte, NLA_ALIGN(length))
	case NLA_NESTED, NLA_NESTED_COMPAT:
		self.Header.Type |= syscall.NLA_F_NESTED
		vbytes := self.Value.(AttrList).Bytes()
		length = syscall.SizeofNlAttr + len(vbytes)
		buf = make([]byte, NLA_ALIGN(length))
		copy(buf[NLA_HDRLEN:], vbytes)
	}
	self.Header.Len = uint16(length)
	*(*syscall.NlAttr)(unsafe.Pointer(&buf[0])) = self.Header
	return buf
}

type AttrList []Attr

func (self AttrList) Get(field uint16) interface{} {
	for _, attr := range []Attr(self) {
		if attr.Field() == field {
			return attr.Value
		}
	}
	return nil
}

func (self AttrList) Bytes() []byte {
	var ret []byte
	for _, attr := range []Attr(self) {
		ret = append(ret, attr.Bytes()...)
	}
	return ret
}

type Policy interface {
	Parse([]byte) (AttrList, error)
}

const NLA_TYPE_MASK = ^uint16(syscall.NLA_F_NESTED | syscall.NLA_F_NET_BYTEORDER)

// SimplePolicy represents non-nested, native byteorder netlink attribute policy.
type SimplePolicy uint16

const (
	NLA_UNSPEC SimplePolicy = iota
	NLA_U8
	NLA_U16
	NLA_U32
	NLA_U64
	NLA_STRING
	NLA_FLAG
	NLA_MSECS
	NLA_NESTED
	NLA_NESTED_COMPAT
	NLA_NUL_STRING
	NLA_BINARY
	NLA_S8
	NLA_S16
	NLA_S32
	NLA_S64
)

func (self SimplePolicy) Parse(nla []byte) (AttrList, error) {
	if attr, err := self.ParseOne(nla); err != nil {
		return nil, err
	} else {
		return []Attr{attr}, nil
	}
}

func (self SimplePolicy) ParseOne(nla []byte) (attr Attr, err error) {
	if len(nla) < NLA_HDRLEN {
		err = NLE_RANGE
		return
	}
	hdr := (*syscall.NlAttr)(unsafe.Pointer(&nla[0]))
	if int(hdr.Len) < NLA_HDRLEN {
		err = NLE_RANGE
		return
	}
	attr.Header = *hdr

	// may add validation and return an error
	switch self {
	default:
		err = NLE_INVAL
	case NLA_U8:
		if int(hdr.Len) != NLA_HDRLEN+1 {
			err = NLE_RANGE
		} else {
			attr.Value = nla[0]
		}
	case NLA_S8:
		if int(hdr.Len) != NLA_HDRLEN+1 {
			err = NLE_RANGE
		} else {
			attr.Value = int8(nla[NLA_HDRLEN])
		}
	case NLA_U16:
		if int(hdr.Len) != NLA_HDRLEN+2 {
			err = NLE_RANGE
		} else {
			attr.Value = *(*uint16)(unsafe.Pointer(&nla[NLA_HDRLEN]))
		}
	case NLA_S16:
		if int(hdr.Len) != NLA_HDRLEN+2 {
			err = NLE_RANGE
		} else {
			attr.Value = *(*int16)(unsafe.Pointer(&nla[NLA_HDRLEN]))
		}
	case NLA_U32:
		if int(hdr.Len) != NLA_HDRLEN+4 {
			err = NLE_RANGE
		} else {
			attr.Value = *(*uint32)(unsafe.Pointer(&nla[NLA_HDRLEN]))
		}
	case NLA_S32:
		if int(hdr.Len) != NLA_HDRLEN+4 {
			err = NLE_RANGE
		} else {
			attr.Value = *(*int32)(unsafe.Pointer(&nla[NLA_HDRLEN]))
		}
	case NLA_U64:
		if int(hdr.Len) != NLA_HDRLEN+8 {
			err = NLE_RANGE
		} else {
			attr.Value = *(*uint64)(unsafe.Pointer(&nla[NLA_HDRLEN]))
		}
	case NLA_S64:
		if int(hdr.Len) != NLA_HDRLEN+8 {
			err = NLE_RANGE
		} else {
			attr.Value = *(*int64)(unsafe.Pointer(&nla[NLA_HDRLEN]))
		}
	case NLA_STRING:
		attr.Value = string(nla[NLA_HDRLEN:hdr.Len])
	case NLA_BINARY:
		attr.Value = nla[NLA_HDRLEN:hdr.Len]
	case NLA_FLAG:
		attr.Value = true
	case NLA_MSECS:
		attr.Value = *(*uint64)(unsafe.Pointer(&nla[NLA_HDRLEN]))
	case NLA_NUL_STRING:
		attr.Value = string(bytes.Split(nla[NLA_HDRLEN:hdr.Len], []byte{0})[0])
	}
	return
}

func NlaStringRemoveNul(a string) string {
	return strings.Split(a, "\x00")[0]
}

func NlaStringEquals(a, b string) bool {
	return NlaStringRemoveNul(a) == NlaStringRemoveNul(b)
}

type ListPolicy struct {
	Nested Policy
}

func (self ListPolicy) Parse(buf []byte) (AttrList, error) {
	var ret []Attr

	switch policy := self.Nested.(type) {
	case SimplePolicy:
		for len(buf) > NLA_HDRLEN {
			if attr, err := policy.ParseOne(buf); err != nil {
				return nil, err
			} else {
				ret = append(ret, attr)
				buf = buf[NLA_ALIGN(int(attr.Header.Len)):]
			}
		}
	default:
		for len(buf) > NLA_HDRLEN {
			hdr := (*syscall.NlAttr)(unsafe.Pointer(&buf[0]))
			if int(hdr.Len) > len(buf) {
				return nil, NLE_RANGE
			}
			if attrs, err := self.Nested.Parse(buf[NLA_HDRLEN:hdr.Len]); err != nil {
				return nil, err
			} else {
				ret = append(ret, Attr{
					Header: *hdr,
					Value:  attrs,
				})
			}
			buf = buf[NLA_ALIGN(int(hdr.Len)):]
		}
	}
	return ret, nil
}

func (self ListPolicy) Dump(attrs AttrList) string {
	var comps []string
	for _, attr := range []Attr(attrs) {
		field := attr.Field()
		switch policy := self.Nested.(type) {
		default:
			comps = append(comps, fmt.Sprintf("%d: %#v", field, attr.Value))
		case MapPolicy:
			comps = append(comps, fmt.Sprintf("%d: %s", field, policy.Dump(attr.Value.(AttrList))))
		case ListPolicy:
			comps = append(comps, fmt.Sprintf("%d: %s", field, policy.Dump(attr.Value.(AttrList))))
		}
	}
	return fmt.Sprintf("[%s]", strings.Join(comps, ", "))
}

var binList Policy = ListPolicy{Nested: NLA_BINARY}

type MapPolicy struct {
	Prefix string
	Names  map[uint16]string
	Rule   map[uint16]Policy
}

func (self MapPolicy) Parse(buf []byte) (AttrList, error) {
	var ret []Attr

	for len(buf) > NLA_HDRLEN {
		hdr := (*syscall.NlAttr)(unsafe.Pointer(&buf[0]))
		if int(hdr.Len) > len(buf) {
			return nil, NLE_RANGE
		}
		attr := Attr{Header: *hdr}
		if p, ok := self.Rule[hdr.Type&NLA_TYPE_MASK]; ok {
			switch policy := p.(type) {
			case SimplePolicy:
				if fattr, err := policy.ParseOne(buf); err != nil {
					return nil, err
				} else {
					attr = fattr
				}
			default:
				if attrs, err := p.Parse(buf[NLA_HDRLEN:hdr.Len]); err != nil {
					return nil, err
				} else {
					attr.Value = attrs
				}
			}
		} else if hdr.Type&syscall.NLA_F_NESTED == 0 {
			attr.Value = buf[NLA_HDRLEN:hdr.Len]
		} else if attrs, err := binList.Parse(buf[NLA_HDRLEN:hdr.Len]); err != nil {
			return nil, err
		} else {
			attr.Value = attrs
		}
		ret = append(ret, attr)
		buf = buf[NLA_ALIGN(int(hdr.Len)):]
	}
	return ret, nil
}

func (self MapPolicy) Dump(attrs AttrList) string {
	var comps []string
	for _, attr := range []Attr(attrs) {
		field := attr.Field()
		name := "?"
		if n, ok := self.Names[field]; ok {
			name = n
		}
		if p, ok := self.Rule[field]; ok {
			switch policy := p.(type) {
			default:
				comps = append(comps, fmt.Sprintf("%s: %#v", name, attr.Value))
			case MapPolicy:
				comps = append(comps, fmt.Sprintf("%s: %s", name, policy.Dump(attr.Value.(AttrList))))
			case ListPolicy:
				comps = append(comps, fmt.Sprintf("%s: %s", name, policy.Dump(attr.Value.(AttrList))))
			}
		}
	}
	return fmt.Sprintf("%s(%s)", self.Prefix, strings.Join(comps, ", "))
}

// error.h

type NlError int

const (
	NLE_SUCCESS NlError = iota
	NLE_FAILURE
	NLE_INTR
	NLE_BAD_SOCK
	NLE_AGAIN
	NLE_NOMEM
	NLE_EXIST
	NLE_INVAL
	NLE_RANGE
	NLE_MSGSIZE
	NLE_OPNOTSUPP
	NLE_AF_NOSUPPORT
	NLE_OBJ_NOTFOUND
	NLE_NOATTR
	NLE_MISSING_ATTR
	NLE_AF_MISMATCH
	NLE_SEQ_MISMATCH
	NLE_MSG_OVERFLOW
	NLE_MSG_TRUNC
	NLE_NOADDR
	NLE_SRCRT_NOSUPPORT
	NLE_MSG_TOOSHORT
	NLE_MSGTYPE_NOSUPPORT
	NLE_OBJ_MISMATCH
	NLE_NOCACHE
	NLE_BUSY
	NLE_PROTO_MISMATCH
	NLE_NOACCESS
	NLE_PERM
	NLE_PKTLOC_FILE
	NLE_PARSE_ERR
	NLE_NODEV
	NLE_IMMUTABLE
	NLE_DUMP_INTR
)

func (self NlError) Error() string {
	switch self {
	default:
		return "Unspecific failure"
	case NLE_SUCCESS:
		return "Success"
	case NLE_FAILURE:
		return "Unspecific failure"
	case NLE_INTR:
		return "Interrupted system call"
	case NLE_BAD_SOCK:
		return "Bad socket"
	case NLE_AGAIN:
		return "Try again"
	case NLE_NOMEM:
		return "Out of memory"
	case NLE_EXIST:
		return "Object exists"
	case NLE_INVAL:
		return "Invalid input data or parameter"
	case NLE_RANGE:
		return "Input data out of range"
	case NLE_MSGSIZE:
		return "Message size not sufficient"
	case NLE_OPNOTSUPP:
		return "Operation not supported"
	case NLE_AF_NOSUPPORT:
		return "Address family not supported"
	case NLE_OBJ_NOTFOUND:
		return "Object not found"
	case NLE_NOATTR:
		return "Attribute not available"
	case NLE_MISSING_ATTR:
		return "Missing attribute"
	case NLE_AF_MISMATCH:
		return "Address family mismatch"
	case NLE_SEQ_MISMATCH:
		return "Message sequence number mismatch"
	case NLE_MSG_OVERFLOW:
		return "Kernel reported message overflow"
	case NLE_MSG_TRUNC:
		return "Kernel reported truncated message"
	case NLE_NOADDR:
		return "Invalid address for specified address family"
	case NLE_SRCRT_NOSUPPORT:
		return "Source based routing not supported"
	case NLE_MSG_TOOSHORT:
		return "Netlink message is too short"
	case NLE_MSGTYPE_NOSUPPORT:
		return "Netlink message type is not supported"
	case NLE_OBJ_MISMATCH:
		return "Object type does not match cache"
	case NLE_NOCACHE:
		return "Unknown or invalid cache type"
	case NLE_BUSY:
		return "Object busy"
	case NLE_PROTO_MISMATCH:
		return "Protocol mismatch"
	case NLE_NOACCESS:
		return "No Access"
	case NLE_PERM:
		return "Operation not permitted"
	case NLE_PKTLOC_FILE:
		return "Unable to open packet location file"
	case NLE_PARSE_ERR:
		return "Unable to parse object"
	case NLE_NODEV:
		return "No such device"
	case NLE_IMMUTABLE:
		return "Immutable attribute"
	case NLE_DUMP_INTR:
		return "Dump inconsistency detected, interrupted"
	}
}

// socket.c

var pidLock = &sync.Mutex{}
var pidUsed = make(map[int]bool)

const (
	NL_SOCK_BUFSIZE_SET = 1 << iota
	NL_SOCK_PASSCRED
	NL_OWN_PORT
	NL_MSG_PEEK
	NL_NO_AUTO_ACK
)

type NlSock struct {
	Local     syscall.SockaddrNetlink
	Peer      syscall.SockaddrNetlink
	Fd        int
	SeqNext   uint32
	SeqExpect uint32
	Flags     int // NL_NO_AUTO_ACK etc.,
}

func NlSocketAlloc() *NlSock {
	tick := uint32(time.Now().Unix())
	return &NlSock{
		Fd: -1,
		Local: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
		},
		Peer: syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
		},
		SeqNext:   tick,
		SeqExpect: tick,
		Flags:     NL_OWN_PORT,
	}
}

func NlSocketFree(sk *NlSock) {
	if sk.Fd >= 0 {
		syscall.Close(sk.Fd)
	}
	pidLock.Lock()
	defer func() {
		pidLock.Unlock()
	}()
	high := sk.Local.Pid >> 22
	delete(pidUsed, int(high))
}

func NlSocketSetBufferSize(sk *NlSock, rxbuf, txbuf int) error {
	if rxbuf <= 0 {
		rxbuf = 32768
	}
	if txbuf <= 0 {
		txbuf = 32768
	}
	if sk.Fd == -1 {
		return NLE_BAD_SOCK
	}
	if err := syscall.SetsockoptInt(sk.Fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, txbuf); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(sk.Fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rxbuf); err != nil {
		return err
	}
	sk.Flags |= NL_SOCK_BUFSIZE_SET
	return nil
}

func NlConnect(sk *NlSock, protocol int) error {
	if sk.Fd != -1 {
		return NLE_BAD_SOCK
	}
	if fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, protocol); err != nil {
		return err
	} else {
		sk.Fd = fd
	}
	if sk.Flags&NL_SOCK_BUFSIZE_SET != 0 {
		if err := NlSocketSetBufferSize(sk, 0, 0); err != nil {
			return err
		}
	}
	if sk.Local.Pid == 0 { // _nl_socket_is_local_port_unspecified
		pid := syscall.Getpid()

		var local *syscall.SockaddrNetlink
		for high := 1023; high > 0; high-- {
			if next := func() bool {
				pidLock.Lock()
				defer func() {
					pidLock.Unlock()
				}()
				if _, exists := pidUsed[high]; !exists {
					pidUsed[high] = true
					return false
				}
				return true
			}(); next {
				continue
			}

			local = &syscall.SockaddrNetlink{
				Pid: uint32((high << 22) | (pid & 0x3FFFFF)),
			}
			if err := syscall.Bind(sk.Fd, local); err == nil {
				break
			} else if err != syscall.EADDRINUSE {
				return err
			} else {
				local = nil
			}
		}
		if local == nil {
			return NLE_EXIST
		}
		sk.Local = *local
		sk.Flags &^= NL_OWN_PORT
	} else {
		if err := syscall.Bind(sk.Fd, &(sk.Local)); err != nil {
			return err
		}
	}
	return nil
}

func NlSocketAddMembership(sk *NlSock, group int) error {
	return syscall.SetsockoptInt(sk.Fd, SOL_NETLINK, syscall.NETLINK_ADD_MEMBERSHIP, group)
}

func NlSocketDropMembership(sk *NlSock, group int) error {
	return syscall.SetsockoptInt(sk.Fd, SOL_NETLINK, syscall.NETLINK_DROP_MEMBERSHIP, group)
}

// msg.c

const NL_AUTO_PORT = 0
const NL_AUTO_SEQ = 0

func NlSendSimple(sk *NlSock, family uint16, flags uint16, buf []byte) error {
	msg := make([]byte, syscall.NLMSG_HDRLEN+NLMSG_ALIGN(len(buf)))
	hdr := (*syscall.NlMsghdr)(unsafe.Pointer(&msg[0]))
	hdr.Type = family
	hdr.Flags = flags
	hdr.Len = syscall.NLMSG_HDRLEN + uint32(len(buf))
	copy(msg[syscall.NLMSG_HDRLEN:], buf)
	NlCompleteMsg(sk, msg)
	return syscall.Sendto(sk.Fd, msg, 0, &sk.Peer)
}

// nl.c

func NlCompleteMsg(sk *NlSock, msg []byte) {
	hdr := (*syscall.NlMsghdr)(unsafe.Pointer(&msg[0]))
	if hdr.Pid == NL_AUTO_PORT {
		hdr.Pid = sk.Local.Pid
	}
	if hdr.Seq == NL_AUTO_SEQ {
		hdr.Seq = sk.SeqNext
		sk.SeqNext++
	}
	hdr.Flags |= syscall.NLM_F_REQUEST
	if sk.Flags&NL_NO_AUTO_ACK == 0 {
		hdr.Flags |= syscall.NLM_F_ACK
	}
}
