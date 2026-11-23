package privatefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// ReadJSON reads a bounded owner-only regular file with one JSON value.
func ReadJSON(path string, destination any) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("expected an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("could not open file")
	}
	defer file.Close()
	const maxSize = 128 << 10
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil || len(data) > maxSize || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return errors.New("could not read JSON record")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("invalid JSON record")
	}
	return nil
}
