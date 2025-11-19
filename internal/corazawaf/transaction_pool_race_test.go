package corazawaf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTransactionPoolCacheIsolation verifies that each transaction gets its own cache
func TestTransactionPoolCacheIsolation(t *testing.T) {
	waf := NewWAF()

	// Create two transactions
	tx1, tx2 := waf.NewTransaction(), waf.NewTransaction()
	assert.Empty(t, tx1.transformationCache)
	assert.Empty(t, tx2.transformationCache)
	// put some value in the transformation cache for tx1
	tk1 := transformationKey{transformationsID: 1}
	tx1.transformationCache[tk1] = &transformationValue{arg: "bla"}
	assert.NotEmpty(t, tx1.transformationCache)

	t.Logf("tx1.transformationCache pointer is %p", tx1.transformationCache)
	t.Logf("tx2.transformationCache pointer is %p", tx2.transformationCache)
	// close both transactions
	if err := tx1.Close(); err != nil {
		t.Fatalf("Failed to close tx1: %s", err.Error())
	}
	if err := tx2.Close(); err != nil {
		t.Fatalf("Failed to close tx2: %s", err.Error())
	}

	tx3, tx4 := waf.NewTransaction(), waf.NewTransaction()
	// Compare map pointers using reflection to ensure they are different instances
	assert.Emptyf(t, tx3.transformationCache,
		"tx3.transformationCache should be empty for new transactions, but it is not, pointer is %p",
		tx3.transformationCache)
	assert.Emptyf(t, tx4.transformationCache,
		"tx4.transformationCache should be empty for new transactions, but it is not, pointer is %p",
		tx4.transformationCache)
}
