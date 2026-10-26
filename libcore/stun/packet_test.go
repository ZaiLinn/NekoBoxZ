package stun

import (
	"encoding/binary"
	"testing"
)

func TestRejectShortAddressAttribute(t *testing.T) {
	// A valid header/transaction and zero-length MAPPED-ADDRESS must not reach rawAddr.
	data := make([]byte, 24)
	binary.BigEndian.PutUint16(data[2:4], 4)
	binary.BigEndian.PutUint32(data[4:8], magicCookie)
	binary.BigEndian.PutUint16(data[20:22], attributeMappedAddress)
	if _, err := newPacketFromBytes(data); err == nil {
		t.Fatal("accepted empty address")
	}
}

func TestAddressAttributeRoundTrip(t *testing.T) {
	p, err := newPacket()
	if err != nil {
		t.Fatal(err)
	}
	p.addAttribute(*newAttribute(attributeMappedAddress, []byte{0, 1, 0, 80, 192, 0, 2, 1}))
	parsed, err := newPacketFromBytes(p.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.getMappedAddr(); got == nil || got.IP() != "192.0.2.1" || got.Port() != 80 {
		t.Fatalf("unexpected address: %v", got)
	}
}

func FuzzPacket(f *testing.F) {
	f.Add([]byte{})
	p, _ := newPacket()
	f.Add(p.bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := newPacketFromBytes(data)
		if err == nil {
			p.getMappedAddr()
			p.getXorMappedAddr()
			p.getChangedAddr()
			p.getOtherAddr()
		}
	})
}
