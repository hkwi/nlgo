package rtlink

import (
	"strings"
)

type IFF uint32

const (
	IFF_UP IFF = 1 << iota
	IFF_BROADCAST
	IFF_DEBUG
	IFF_LOOPBACK
	IFF_POINTOPOINT
	IFF_NOTRAILERS
	IFF_RUNNING
	IFF_NOARP
	IFF_PROMISC
	IFF_ALLMULTI
	IFF_MASTER
	IFF_SLAVE
	IFF_MULTICAST
	IFF_PORTSEL
	IFF_AUTOMEDIA
	IFF_DYNAMIC
	IFF_LOWER_UP
	IFF_DORMANT
	IFF_ECHO
)

var names = []string{
	"IFF_UP IFF",
	"IFF_BROADCAST",
	"IFF_DEBUG",
	"IFF_LOOPBACK",
	"IFF_POINTOPOINT",
	"IFF_NOTRAILERS",
	"IFF_RUNNING",
	"IFF_NOARP",
	"IFF_PROMISC",
	"IFF_ALLMULTI",
	"IFF_MASTER",
	"IFF_SLAVE",
	"IFF_MULTICAST",
	"IFF_PORTSEL",
	"IFF_AUTOMEDIA",
	"IFF_DYNAMIC",
	"IFF_LOWER_UP",
	"IFF_DORMANT",
	"IFF_ECHO",
}

func (self IFF) String() string {
	var ret []string
	for i := uint8(0); i < 32; i++ {
		if self&(1<<i) != 0 {
			ret = append(ret, names[i])
		}
	}
	return strings.Join(ret, ",")
}
