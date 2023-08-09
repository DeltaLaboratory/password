package password

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestGenerate(t *testing.T) {
	_, err := Generate([]byte("password"))
	if err != nil {
		t.Fatalf("failed to generate password: %s", err)
	}
}

func TestVerify(t *testing.T) {
	hash, err := Generate([]byte("password"))
	if err != nil {
		t.Fatalf("failed to generate password: %s", err)
	}

	ok, err := Verify([]byte("password"), hash)
	if err != nil {
		t.Fatalf("failed to verify password: %s", err)
	}
	if !ok {
		t.Fatalf("password verification failed")
	}
}

func BenchmarkGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := Generate([]byte("password"))
		if err != nil {
			b.Fatalf("failed to generate password: %s", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	hash, err := Generate([]byte("password"))
	if err != nil {
		b.Fatalf("failed to generate password: %s", err)
	}

	for i := 0; i < b.N; i++ {
		ok, err := Verify([]byte("password"), hash)
		if err != nil {
			b.Fatalf("failed to verify password: %s", err)
		}
		if !ok {
			b.Fatalf("password verification failed")
		}
	}
}

func ExampleGenerate() {
	hash, err := Generate([]byte("password"), []byte("salt            "))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Hash: %x\n", hash)
	// output: Hash: 73616c7420202020202020202020202056a3984c5b69cbc7819ff6097dc4fb65f154d5509d0c021f6bc8e7c135253eb3
}

func ExampleVerify() {
	hash, _ := hex.DecodeString("73616c7420202020202020202020202056a3984c5b69cbc7819ff6097dc4fb65f154d5509d0c021f6bc8e7c135253eb3")
	ok, err := Verify([]byte("password"), hash)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Password verification: %t\n", ok)
	// output: Password verification: true
}
