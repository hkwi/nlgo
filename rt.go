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
		IFLA_PORT_VF:            NLA_U32,
		IFLA_PORT_PROFILE:       NLA_STRING,
		IFLA_PORT_VSI_TYPE:      NLA_BINARY,
		IFLA_PORT_INSTANCE_UUID: NLA_BINARY,
		IFLA_PORT_HOST_UUID:     NLA_STRING,
		IFLA_PORT_REQUEST:       NLA_U8,
		IFLA_PORT_RESPONSE:      NLA_U16,
	},
}

var RouteLinkPolicy MapPolicy = MapPolicy{
	Prefix: "IFLA",
	Names:  IFLA_itoa,
	Rule: map[uint16]Policy{
		IFLA_IFNAME:    NLA_STRING,
		IFLA_ADDRESS:   NLA_BINARY,
		IFLA_BROADCAST: NLA_BINARY,
		IFLA_MAP:       NLA_BINARY,
		IFLA_MTU:       NLA_U32,
		IFLA_LINK:      NLA_U32,
		IFLA_MASTER:    NLA_U32,
		IFLA_CARRIER:   NLA_U8,
		IFLA_TXQLEN:    NLA_U32,
		IFLA_WEIGHT:    NLA_U32,
		IFLA_OPERSTATE: NLA_U8,
		IFLA_LINKMODE:  NLA_U8,
		IFLA_LINKINFO: MapPolicy{
			Prefix: "INFO",
			Names:  IFLA_INFO_itoa,
			Rule: map[uint16]Policy{
				IFLA_INFO_KIND:       NLA_STRING,
				IFLA_INFO_DATA:       NLA_BINARY, // depends on the kind
				IFLA_INFO_SLAVE_KIND: NLA_STRING,
				IFLA_INFO_SLAVE_DATA: NLA_BINARY, // depends on the kind
			},
		},
		IFLA_NET_NS_PID: NLA_U32,
		IFLA_NET_NS_FD:  NLA_U32,
		IFLA_IFALIAS:    NLA_STRING,
		IFLA_VFINFO_LIST: ListPolicy{
			Nested: MapPolicy{
				Prefix: "VF",
				Names:  IFLA_VF_itoa,
				Rule: map[uint16]Policy{
					IFLA_VF_MAC:        NLA_BINARY,
					IFLA_VF_VLAN:       NLA_BINARY,
					IFLA_VF_TX_RATE:    NLA_BINARY,
					IFLA_VF_SPOOFCHK:   NLA_BINARY,
					IFLA_VF_LINK_STATE: NLA_BINARY,
					IFLA_VF_RATE:       NLA_BINARY,
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
		IFLA_AF_SPEC:         NLA_BINARY, // depends on spec
		IFLA_EXT_MASK:        NLA_U32,
		IFLA_PROMISCUITY:     NLA_U32,
		IFLA_NUM_TX_QUEUES:   NLA_U32,
		IFLA_NUM_RX_QUEUES:   NLA_U32,
		IFLA_PHYS_PORT_ID:    NLA_BINARY,
		IFLA_CARRIER_CHANGES: NLA_U32,

		IFLA_QDISC:    NLA_STRING,
		IFLA_STATS:    NLA_BINARY, // struct rtnl_link_stats
		IFLA_STATS64:  NLA_BINARY, // struct rtnl_link_stats64
		IFLA_WIRELESS: NLA_BINARY,
		IFLA_PROTINFO: NLA_BINARY, // depends on prot
		IFLA_NUM_VF:   NLA_U32,
		IFLA_GROUP:    NLA_U32,
	},
}
