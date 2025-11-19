package corazawaf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTransactionPoolCacheIsolation verifies that each transaction gets its own cache
func TestTransactionPoolCacheIsolation(t *testing.T) {
	waf := NewWAF()

	// Create the first transactions
	tx1 := waf.NewTransaction()
	assert.Empty(t, tx1.transformationCache)
	// put some value in the transformation cache for tx1
	tk1 := transformationKey{transformationsID: 1}
	tx1.transformationCache[tk1] = &transformationValue{arg: "bla"}
	assert.NotEmpty(t, tx1.transformationCache)

	t.Logf("tx1.transformationCache pointer is %p", tx1.transformationCache)
	// close both transactions
	if err := tx1.Close(); err != nil {
		t.Fatalf("Failed to close tx1: %s", err.Error())
	}

	tx2 := waf.NewTransaction()
	assert.Empty(t, tx2.transformationCache)

	t.Logf("tx2.transformationCache pointer is %p", tx2.transformationCache)
	if err := tx2.Close(); err != nil {
		t.Fatalf("Failed to close tx2: %s", err.Error())
	}

	tx3, tx4 := waf.NewTransaction(), waf.NewTransaction()

	t.Logf("\ntx1.transformationCache pointer is %p\n"+
		"tx2.tranformactionCache pointer is %p\n"+
		"tx3.tranformactionCache pointer is %p\n"+
		"tx4.tranformactionCache pointer is %p\n",
		tx1.transformationCache,
		tx2.transformationCache,
		tx3.transformationCache,
		tx4.transformationCache)

	assert.Empty(t, tx3.transformationCache)
	assert.Empty(t, tx4.transformationCache)
}
