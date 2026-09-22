package extract

import (
	"reflect"
	"testing"
)

func TestASCIIStrings(t *testing.T) {
	data := []byte("\x00\x01garbage\x02hello world\x00\x03ab\x04longer-string-here\x00")
	got := ASCIIStrings(data, 5)
	want := []string{"garbage", "hello world", "longer-string-here"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ASCIIStrings() = %v, want %v", got, want)
	}
}

func TestASCIIStrings_MinLenFilters(t *testing.T) {
	data := []byte("ab\x00abcde\x00abc\x00")
	got := ASCIIStrings(data, 5)
	want := []string{"abcde"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ASCIIStrings() = %v, want %v", got, want)
	}
}

// utf16le encodes an ASCII string as UTF-16LE bytes, the way a Windows
// binary would store a wide-char string.
func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, c := range s {
		out = append(out, byte(c), 0x00)
	}
	return out
}

func TestUTF16LEStrings(t *testing.T) {
	var data []byte
	data = append(data, 0xFF, 0xFE) // BOM-like noise, not a valid pair
	data = append(data, utf16le("evil-c2-domain.com")...)
	data = append(data, 0x00, 0x00)       // terminator, breaks the run
	data = append(data, utf16le("ab")...) // too short, should be dropped
	data = append(data, 0x00, 0x00)
	data = append(data, utf16le("another-wide-string")...)

	got := UTF16LEStrings(data, 5)
	want := []string{"evil-c2-domain.com", "another-wide-string"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UTF16LEStrings() = %v, want %v", got, want)
	}
}
