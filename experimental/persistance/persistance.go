package persistanceimport

import (
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/persistance/ptypes"
)

// SetEngine returns a **new** WAFConfig instance with the specified persistence engine configured.
// The provided engine will be initialized using its Init method.
// If the provided engine is nil, the resulting config will effectively disable persistence
// NOTE: This function and the persistence feature are experimental and subject to change.
func SetEngine(config coraza.WAFConfig, engine ptypes.PersistentEngine) (coraza.WAFConfig, error) {
	cfgImpl, ok := config.(interface {
		WithPersistenceEngine(persistenceEngine ptypes.PersistentEngine) coraza.WAFConfig
	})
	if !ok {
		return nil, fmt.Errorf("unsupported WAFConfig type %T, cannot clone or set engine", config)
	}
	return cfgImpl.WithPersistenceEngine(engine), nil
}
