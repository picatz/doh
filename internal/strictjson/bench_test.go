package strictjson_test

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/picatz/doh/internal/strictjson"
)

// manyObjects returns an array of {"k":1} objects of about size bytes, the
// shape that made a tree-building checker allocate about 170 times its input.
func manyObjects(size int) []byte {
	const element = `{"k":1},`
	var b bytes.Buffer
	b.Grow(size + len(element))
	b.WriteByte('[')
	for b.Len() < size {
		b.WriteString(element)
	}
	b.WriteString(`{"k":1}]`)
	return b.Bytes()
}

type kRecord struct {
	K int `json:"k"`
}

const benchSize = 15 << 20

func BenchmarkCheck(b *testing.B) {
	data := manyObjects(benchSize)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := strictjson.Check(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalOpen(b *testing.B) {
	data := manyObjects(benchSize)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		var v []kRecord
		if err := strictjson.UnmarshalOpen(data, &v); err != nil {
			b.Fatal(err)
		}
	}
}

// TestAllocationIsLinearAndSmall bounds what checking costs: scanning a
// 15 MiB array of small objects must allocate far less than its input.
func TestAllocationIsLinearAndSmall(t *testing.T) {
	data := manyObjects(benchSize)
	allocated := func(f func()) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	if got := allocated(func() {
		if err := strictjson.Check(data); err != nil {
			t.Fatal(err)
		}
	}); got > uint64(len(data))/4 {
		t.Errorf("Check allocated %d bytes for %d bytes of input", got, len(data))
	}
	// Decoding into a type that stores nothing isolates the strict scan from
	// the memory the caller's own result needs.
	var sink []struct{}
	if got := allocated(func() {
		if err := strictjson.UnmarshalOpen(data, &sink); err != nil {
			t.Fatal(err)
		}
	}); got > uint64(len(data))*3 {
		t.Errorf("UnmarshalOpen allocated %d bytes for %d bytes of input, want under 3x", got, len(data))
	}
}
