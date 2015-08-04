// +build ignore

package nlgo

/*
#include <sys/socket.h>
#include <linux/rtnetlink.h>
*/
import "C"

type Ndmsg C.struct_ndmsg

type Tcmsg C.struct_tcmsg

const (
	SizeofNdmsg = C.sizeof_struct_ndmsg
	SizeofTcmsg = C.sizeof_struct_tcmsg
)

