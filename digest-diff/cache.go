package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Cache struct {
	dir string
}

func NewCache(dir string) *Cache {
	return &Cache{dir: dir}
}

func (c *Cache) Get(key string) (*DiffResult, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, key+".json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result DiffResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("corrupt cache entry %s: %w", key, err)
	}
	return &result, nil
}

func (c *Cache) Set(key string, result *DiffResult) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	return writeJSON(filepath.Join(c.dir, key+".json"), result)
}
