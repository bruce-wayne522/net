package proxy

import (
	"bytes"
	"math/big"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func Base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	var zeroCount int
	for _, b := range input {
		if b != 0 {
			break
		}
		zeroCount++
	}
	num := new(big.Int).SetBytes(input)
	var result []byte
	base := big.NewInt(58)
	zero := big.NewInt(0)
	for num.Cmp(zero) > 0 {
		mod := new(big.Int)
		num.DivMod(num, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	for i := 0; i < zeroCount; i++ {
		result = append([]byte{alphabet[0]}, result...)
	}
	return string(result)
}

func Base58Decode(input string) []byte {
	if len(input) == 0 {
		return []byte{}
	}
	var zeroCount int
	for _, r := range input {
		if r != rune(alphabet[0]) {
			break
		}
		zeroCount++
	}
	num := big.NewInt(0)
	base := big.NewInt(58)
	for _, r := range input {
		index := bytes.IndexRune([]byte(alphabet), r)
		if index == -1 {
			return []byte{}
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(index)))
	}
	result := num.Bytes()
	for i := 0; i < zeroCount; i++ {
		result = append([]byte{0}, result...)
	}
	return result
}
