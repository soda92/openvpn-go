package config

import (
	"bytes"
	"testing"
)

func TestParseStaticKey(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			b.WriteString("ab")
		}
		b.WriteString("\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")

	key, err := ParseStaticKey(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 256 {
		t.Fatalf("key len = %d, want 256", len(key))
	}
	for _, v := range key {
		if v != 0xab {
			t.Fatalf("unexpected key byte %x", v)
		}
	}

	if _, err := ParseStaticKey([]byte("deadbeef")); err == nil {
		t.Fatal("short key accepted")
	}
}
