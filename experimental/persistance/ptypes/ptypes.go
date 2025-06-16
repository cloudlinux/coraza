package ptypes

// PersistenceEngineProvider provider for creation of PersistentEngine.
// This way we don't have to worry about cloning when using
// WithPersistenceEngineProvider in config.go
type PersistenceEngineProvider func() (PersistentEngine, error)

// PersistentEngine defines the interface for storing and retrieving persistent collection data (e.g., SESSION, IP, GLOBAL).
type PersistentEngine interface {
	// Close releases engine resources.
	Close() error
	// Sum increments or decrements a numeric value.
	Sum(collectionName string, collectionKey string, key string, delta int) error
	// Get retrieves a specific value.
	Get(collectionName string, collectionKey string, key string) (string, error)
	// All retrieves all key-value pairs for a collection key.
	All(collectionName string, collectionKey string) (map[string]string, error)
	// Set stores a value, overwriting any existing one.
	Set(collection string, collectionKey string, key string, value string) error
	// SetTTL sets the Time-To-Live (in seconds) for a specific key within a collection instance.
	SetTTL(collection string, collectionKey string, key string, ttl int) error
	// Remove deletes a specific key.
	Remove(collection string, collectionKey string, key string) error
}
