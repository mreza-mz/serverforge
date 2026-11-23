// Package privatefile publishes new owner-only files atomically.
package privatefile

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrExists = errors.New("destination already exists")

// WriteNew publishes a complete file without replacing an existing path.
func WriteNew(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".serverforge-*")
	if err != nil {
		return errors.New("could not create a file in the destination directory")
	}
	defer os.Remove(file.Name())
	defer file.Close()

	if err := file.Chmod(0600); err != nil {
		return errors.New("could not set file permissions")
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("could not write file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("could not sync file")
	}
	if err := file.Close(); err != nil {
		return errors.New("could not close file")
	}
	err = os.Link(file.Name(), path)
	if errors.Is(err, os.ErrExist) {
		return ErrExists
	}
	if err != nil {
		return errors.New("could not publish file in the destination directory")
	}
	return nil
}
