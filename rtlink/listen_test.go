package rtlink

import (
	"github.com/hkwi/nlgo"
	"testing"
)

func TestListener(t *testing.T) {
	sock, e1 := NewListener()
	if e1 != nil {
		t.Error(e1)
	}
	if msgs, err := sock.Recv(); err != nil {
		t.Error(err)
	} else {
		for _, msg := range msgs {
			t.Log(msg.Index, msg.Attrs.(nlgo.AttrMap).Get(nlgo.IFLA_IFNAME))
		}
	}
}
