package main

import (
	"math/rand"
	"testing"
)

/*
BenchmarkIntTobytes-4           30000000                49.8 ns/op
BenchmarkInt2bytes-4            50000000                35.4 ns/op
BenchmarkBytes2int-4            30000000                95.0 ns/op
BenchmarkBytesToint-4            1000000              1089 ns/op
PASS
ok      MyGolang/Socks5 8.401s
*/
func BenchmarkIntTobytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		v := 1024 + rand.Int31n(9999)
		intTobytes(int(v), 2)
	}
}

func BenchmarkInt2bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		v := 1024 + rand.Int31n(9999)
		int2bytes(int(v), 2)
	}
}

func BenchmarkBytes2int(b *testing.B) {
	bp := make([]byte, rand.Int31n(100))
	for i := 0; i < len(bp); i++ {
		bp[i] = byte(rand.Int31n(256))
	}
	for i := 0; i < b.N; i++ {
		bytes2int(bp)
	}
}

func BenchmarkBytesToint(b *testing.B) {
	bp := make([]byte, rand.Int31n(100))
	for i := 0; i < len(bp); i++ {
		bp[i] = byte(rand.Int31n(256))
	}
	for i := 0; i < b.N; i++ {
		bytesToint(bp)
	}
}
