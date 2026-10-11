package sshaudit

import (
	"encoding/binary"
	"testing"
)

func utmpRec(typ uint16, line, user, host string, ts int32) []byte {
	r := make([]byte, utmpSize)
	binary.LittleEndian.PutUint16(r[0:], typ)
	copy(r[8:], line)
	copy(r[44:], user)
	copy(r[76:], host)
	binary.LittleEndian.PutUint32(r[340:], uint32(ts))
	return r
}

func TestParseWtmp(t *testing.T) {
	var data []byte
	data = append(data, utmpRec(7, "pts/0", "alice", "1.2.3.4", 1000)...)
	data = append(data, utmpRec(2, "~", "reboot", "6.12", 1500)...) // boot record: ignored
	data = append(data, utmpRec(7, "tty1", "root", "", 1800)...)    // local login: ignored
	data = append(data, utmpRec(7, "pts/1", "bob", "5.6.7.8", 2000)...)
	got := parseWtmp(data, 10)
	if len(got) != 2 || got[0].User != "bob" || got[1].User != "alice" || got[0].From != "5.6.7.8" || got[0].TTY != "pts/1" || got[0].Time.Unix() != 2000 {
		t.Fatalf("parseWtmp = %+v", got)
	}
	if len(parseWtmp(data, 1)) != 1 {
		t.Fatal("limit not applied")
	}
	if parseWtmp([]byte("garbage"), 5) != nil {
		t.Fatal("short data should yield nothing")
	}
}
