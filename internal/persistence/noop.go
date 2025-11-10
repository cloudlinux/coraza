package persistence

type NoopEngine struct{}

func (NoopEngine) Close() error {
	return nil
}

func (NoopEngine) Sum(collectionName string, collectionKey string, key string, sum int) error {
	return nil
}

func (NoopEngine) Get(collectionName string, collectionKey string, key string) (string, error) {
	return "", nil
}

func (NoopEngine) Set(collection string, collectionKey string, key string, value string) error {
	return nil
}

func (NoopEngine) Remove(collection string, collectionKey string, key string) error {
	return nil
}

func (NoopEngine) All(collection string, collectionKey string) (map[string]string, error) {
	return nil, nil
}

func (NoopEngine) SetTTL(collection string, collectionKey string, key string, ttl int) error {
	return nil
}
