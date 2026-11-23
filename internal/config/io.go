package config

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/mreza-mz/serverforge/internal/privatefile"
	"go.yaml.in/yaml/v3"
)

const maxProfileSize = 128 << 10

func Load(path string) (Profile, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Profile{}, errors.New("profile must be a readable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Profile{}, errors.New("could not open profile")
	}
	defer file.Close()
	return Parse(file)
}

func Parse(reader io.Reader) (Profile, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxProfileSize+1))
	if err != nil {
		return Profile{}, errors.New("could not read profile")
	}
	if len(data) > maxProfileSize {
		return Profile{}, errors.New("profile exceeds 128 KiB")
	}

	// YAML decoder errors can quote input, including accidentally pasted secrets.
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&doc) != nil || !plainYAML(&doc, 0) || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return Profile{}, errors.New("profile must be a YAML mapping without aliases or custom tags")
	}
	if decoder.Decode(new(yaml.Node)) != io.EOF {
		return Profile{}, errors.New("profile must contain exactly one YAML document")
	}
	root := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "security" {
			if err := validateSecurityYAML(root.Content[i+1]); err != nil {
				return Profile{}, err
			}
		}
	}
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	var profile Profile
	if strict.Decode(&profile) != nil {
		return Profile{}, errors.New("profile fields must match the schema with no duplicate or unknown keys")
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func plainYAML(node *yaml.Node, depth int) bool {
	if depth > 16 || node.Anchor != "" {
		return false
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.MappingNode, yaml.SequenceNode:
		if node.Kind == yaml.MappingNode {
			for i := 0; i < len(node.Content); i += 2 {
				key := node.Content[i]
				if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Value == "<<" {
					return false
				}
			}
		}
		for _, child := range node.Content {
			if !plainYAML(child, depth+1) {
				return false
			}
		}
		return node.Kind == yaml.DocumentNode || node.ShortTag() == "!!map" || node.ShortTag() == "!!seq"
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!str", "!!int", "!!bool":
			return true
		}
	}
	return false
}

func validateSecurityYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("security must be a mapping")
	}
	for i := 1; i < len(node.Content); i += 2 {
		value := node.Content[i]
		if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!bool" || (value.Value != "true" && value.Value != "false") {
			return errors.New("security choices must be explicit YAML booleans (true or false)")
		}
	}
	return nil
}

// SaveNew publishes a complete, owner-only profile and never replaces an existing file.
func SaveNew(path string, profile Profile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(profile)
	if err != nil {
		return errors.New("could not encode profile")
	}
	if len(data) > maxProfileSize {
		return errors.New("profile exceeds 128 KiB")
	}

	if err := privatefile.WriteNew(path, data); err != nil {
		if errors.Is(err, privatefile.ErrExists) {
			return errors.New("profile already exists")
		}
		return err
	}
	return nil
}
