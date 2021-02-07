package main

import "math"

//deprecated
func bytesToint(b []byte) int {
	unit := 256
	sum := 0
	for n := len(b); n > 0; n-- {
		sum += int(b[len(b)-n]) * int(math.Pow(float64(unit), float64(n-1)))
	}
	return sum
}

//deprecated
func intTobytes(n int, length int) []byte {
	unit := 256
	b := make([]byte, length)
	b[0] = byte(n % unit)
	for i := n / unit; i >= unit; i /= unit {
		b = append(b, byte(i%unit))
	}
	bigBytes := make([]byte, len(b))
	for n, v := range b {
		bigBytes[len(b)-n-1] = v
	}
	return bigBytes
}
