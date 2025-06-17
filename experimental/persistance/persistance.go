package persistance

import (
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/persistance/ptypes"
)

// SetEngine returns a **new** WAFConfig instance with the specified persistence engine configured.
// The provided engine will be initialized using its Init method.
// If the provided engine is nil, the resulting config will effectively disable persistence
// NOTE: This function and the persistence feature are experimental and subject to change.
func SetEngine(config coraza.WAFConfig, engineProvider ptypes.PersistenceEngineProvider) (coraza.WAFConfig, error) {
	cfgImpl, ok := config.(interface {
		WithPersistenceEngineProvider(provider ptypes.PersistenceEngineProvider) coraza.WAFConfig
	})
	if !ok {
		return nil, fmt.Errorf("unsupported WAFConfig type %T, cannot clone or set engine", config)
	}
	return cfgImpl.WithPersistenceEngineProvider(engineProvider), nil
}

// ClosePersistentEngine provides a way to gracefully shut down the persistence engine
// associated with a WAF instance. Since the WAF instance manages the engine's lifecycle,
// this helper should be called when the WAF instance is no longer needed, for example,
// during an application shutdown or a configuration reload.
//
// This allows the engine to release resources, such as database connections or
// background garbage collection goroutines.
//
// NOTE: This function and the persistence feature are experimental and subject to change.
func ClosePersistentEngine(waf coraza.WAF) error {
	wafImpl, ok := waf.(interface {
		ClosePersistentEngine() error
	})
	if !ok {
		return fmt.Errorf("unsupported WAF type %T, cannot close engine", waf)
	}
	return wafImpl.ClosePersistentEngine()
}
