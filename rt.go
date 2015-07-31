// +build linux

package nlgo

const (
	IFLA_UNSPEC = iota
	IFLA_ADDRESS
	IFLA_BROADCAST
	IFLA_IFNAME
	IFLA_MTU
	IFLA_LINK // used with 8021q, for example
	IFLA_QDISC
	IFLA_STATS
	IFLA_COST
	IFLA_PRIORITY
	IFLA_MASTER
	IFLA_WIRELESS
	IFLA_PROTINFO
	IFLA_TXQLEN
	IFLA_MAP
	IFLA_WEIGHT
	IFLA_OPERSTATE
	IFLA_LINKMODE
	IFLA_LINKINFO
	IFLA_NET_NS_PID
	IFLA_IFALIAS
	IFLA_NUM_VF
	IFLA_VFINFO_LIST
	IFLA_STATS64
	IFLA_VF_PORTS
	IFLA_PORT_SELF
	IFLA_AF_SPEC
	IFLA_GROUP
	IFLA_NET_NS_FD
	IFLA_EXT_MASK
	IFLA_PROMISCUITY
	IFLA_NUM_TX_QUEUES
	IFLA_NUM_RX_QUEUES
	IFLA_CARRIER
	IFLA_PHYS_PORT_ID
	IFLA_CARRIER_CHANGES
)

const (
	IFLA_INFO_UNSPEC = iota
	IFLA_INFO_KIND
	IFLA_INFO_DATA
	IFLA_INFO_XSTATS
	IFLA_INFO_SLAVE_KIND
	IFLA_INFO_SLAVE_DATA
)

const (
	IFLA_VF_UNSPEC = iota
	IFLA_VF_MAC
	IFLA_VF_VLAN
	IFLA_VF_TX_RATE
	IFLA_VF_SPOOFCHK
	IFLA_VF_LINK_STATE
	IFLA_VF_RATE
)

const (
	IFLA_VF_PORT_UNSPEC = iota
	IFLA_VF_PORT
)

const (
	IFLA_PORT_UNSPEC = iota
	IFLA_PORT_VF
	IFLA_PORT_PROFILE
	IFLA_PORT_VSI_TYPE
	IFLA_PORT_INSTANCE_UUID
	IFLA_PORT_HOST_UUID
	IFLA_PORT_REQUEST
	IFLA_PORT_RESPONSE
)

// RtnlLinkStats64 will be the contents for IFLA_STATS64.
type RtnlLinkStats64 struct {
	RxPackets  uint64
	TxPackets  uint64
	RxBytes    uint64
	TxBytes    uint64
	RxErrors   uint64
	TxErrors   uint64
	RxDropped  uint64
	TxDropped  uint64
	Multicast  uint64
	Collisions uint64
	// detailed rx_errors
	RxLengthErrors uint64
	RxOverErrors   uint64
	RxCrcErrors    uint64
	RxFrameErrors  uint64
	RxFifoErrors   uint64
	RxMissedErrors uint64
	// detailed tx_errors
	TxAbortedErrors   uint64
	TxCarrierErrors   uint64
	TxFifoErrors      uint64
	TxHeartbeatErrors uint64
	TxWindowErrors    uint64
	// cslip etc.
	RxCompressed uint64
	TxCompressed uint64
}

var portPolicy Policy = MapPolicy{
	Prefix: "IFLA_PORT",
	Names:  IFLA_PORT_itoa,
	Rule: map[uint16]Policy{
		IFLA_PORT_VF:            U32Policy,
		IFLA_PORT_PROFILE:       StringPolicy,
		IFLA_PORT_VSI_TYPE:      StringPolicy,
		IFLA_PORT_INSTANCE_UUID: StringPolicy,
		IFLA_PORT_HOST_UUID:     StringPolicy,
		IFLA_PORT_REQUEST:       U8Policy,
		IFLA_PORT_RESPONSE:      U16Policy,
	},
}

var RouteLinkPolicy MapPolicy = MapPolicy{
	Prefix: "IFLA",
	Names:  IFLA_itoa,
	Rule: map[uint16]Policy{
		IFLA_IFNAME:    NulStringPolicy,
		IFLA_ADDRESS:   StringPolicy,
		IFLA_BROADCAST: StringPolicy,
		IFLA_MAP:       StringPolicy,
		IFLA_MTU:       U32Policy,
		IFLA_LINK:      U32Policy,
		IFLA_MASTER:    U32Policy,
		IFLA_CARRIER:   U8Policy,
		IFLA_TXQLEN:    U32Policy,
		IFLA_WEIGHT:    U32Policy,
		IFLA_OPERSTATE: U8Policy,
		IFLA_LINKMODE:  U8Policy,
		IFLA_LINKINFO: MapPolicy{
			Prefix: "INFO",
			Names:  IFLA_INFO_itoa,
			Rule: map[uint16]Policy{
				IFLA_INFO_KIND:       StringPolicy,
				IFLA_INFO_DATA:       StringPolicy, // depends on the kind
				IFLA_INFO_SLAVE_KIND: StringPolicy,
				IFLA_INFO_SLAVE_DATA: StringPolicy, // depends on the kind
			},
		},
		IFLA_NET_NS_PID: U32Policy,
		IFLA_NET_NS_FD:  U32Policy,
		IFLA_IFALIAS:    StringPolicy,
		IFLA_VFINFO_LIST: ListPolicy{
			Nested: MapPolicy{
				Prefix: "VF",
				Names:  IFLA_VF_itoa,
				Rule: map[uint16]Policy{
					IFLA_VF_MAC:        StringPolicy,
					IFLA_VF_VLAN:       StringPolicy,
					IFLA_VF_TX_RATE:    StringPolicy,
					IFLA_VF_SPOOFCHK:   StringPolicy,
					IFLA_VF_LINK_STATE: StringPolicy,
					IFLA_VF_RATE:       StringPolicy,
				},
			},
		},
		IFLA_VF_PORTS: ListPolicy{
			Nested: MapPolicy{
				Prefix: "VF_PORT",
				Names:  IFLA_VF_PORT_itoa,
				Rule: map[uint16]Policy{
					IFLA_VF_PORT: portPolicy,
				},
			},
		},
		IFLA_PORT_SELF:       portPolicy,
		IFLA_AF_SPEC:         StringPolicy, // depends on spec
		IFLA_EXT_MASK:        U32Policy,
		IFLA_PROMISCUITY:     U32Policy,
		IFLA_NUM_TX_QUEUES:   U32Policy,
		IFLA_NUM_RX_QUEUES:   U32Policy,
		IFLA_PHYS_PORT_ID:    StringPolicy,
		IFLA_CARRIER_CHANGES: U32Policy,

		IFLA_QDISC:    StringPolicy,
		IFLA_STATS:    StringPolicy, // struct rtnl_link_stats
		IFLA_STATS64:  StringPolicy, // struct rtnl_link_stats64
		IFLA_WIRELESS: StringPolicy,
		IFLA_PROTINFO: StringPolicy, // depends on prot
		IFLA_NUM_VF:   U32Policy,
		IFLA_GROUP:    U32Policy,
	},
}
