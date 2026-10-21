package cache

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheBasic(t *testing.T) {
	c := New[string](50*time.Millisecond, 1000)

	// Set and Get
	c.Set("k1", "v1")
	if v, ok := c.Get("k1"); !ok || v != "v1" {
		t.Fatalf("expected v1, got %v (ok=%v)", v, ok)
	}

	// Delete
	c.Delete("k1")
	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected k1 to be deleted")
	}

	// Expiration
	c.Set("k2", "v2")
	time.Sleep(60 * time.Millisecond)
	if _, ok := c.Get("k2"); ok {
		t.Fatal("expected k2 to be expired")
	}
}

func TestCacheGetOrLoad(t *testing.T) {
	c := New[int](time.Second, 1000)
	var loadCalls int32

	loader := func() (int, error) {
		atomic.AddInt32(&loadCalls, 1)
		time.Sleep(10 * time.Millisecond)
		return 42, nil
	}

	var wg sync.WaitGroup
	results := make([]int, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			val, err := c.GetOrLoad("shared-key", loader)
			if err != nil {
				t.Errorf("GetOrLoad error: %v", err)
			}
			results[idx] = val
		}(i)
	}
	wg.Wait()

	if calls := atomic.LoadInt32(&loadCalls); calls != 1 {
		t.Errorf("expected exactly 1 loader call due to singleflight coalescing, got %d", calls)
	}

	for _, res := range results {
		if res != 42 {
			t.Errorf("expected result 42, got %d", res)
		}
	}
}

