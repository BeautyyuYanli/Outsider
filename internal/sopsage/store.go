package sopsage

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var validEnvNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// IsValidEnvName returns true if name is a valid POSIX environment variable identifier.
func IsValidEnvName(name string) bool {
	return validEnvNameRe.MatchString(name)
}

// KV represents a single key-value pair with wipeable byte value.
type KV struct {
	Key   string
	Value []byte
}

// WipeKVs zeroes all value buffers in a slice of KV.
func WipeKVs(kvs []KV) {
	for i := range kvs {
		clear(kvs[i].Value)
		kvs[i].Value = nil
	}
}

// KeyInfo describes a plaintext leaf key discovered in a SOPS YAML file.
type KeyInfo struct {
	Path        string
	IsEncrypted bool
}

// FileMeta holds unencrypted structural metadata inspected from a SOPS YAML file.
type FileMeta struct {
	Recipients       []string
	Keys             []KeyInfo
	KeySet           map[string]bool
	LastModified     string
	MAC              string
	MACOnlyEncrypted bool
}

type ageKeyEntry struct {
	Recipient string `yaml:"recipient"`
	Enc       string `yaml:"enc"`
}

type sopsMetadata struct {
	Age              []ageKeyEntry `yaml:"age"`
	LastModified     string        `yaml:"lastmodified"`
	MAC              string        `yaml:"mac"`
	MACOnlyEncrypted bool          `yaml:"mac_only_encrypted,omitempty"`
	Version          string        `yaml:"version,omitempty"`
}

// parseYAMLDocument loads a YAML file into a yaml.Node document root and its top-level mapping node.
func parseYAMLDocument(path string) (*yaml.Node, *yaml.Node, *sopsMetadata, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: read %s: %v", ErrInvalidFormat, path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: parse YAML %s: %v", ErrInvalidFormat, path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: empty YAML document %s", ErrInvalidFormat, path)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, nil, fmt.Errorf("%w: root YAML node must be a mapping", ErrInvalidFormat)
	}
	sopsNode := findMapValue(root, "sops")
	if sopsNode == nil || sopsNode.Kind != yaml.MappingNode {
		return nil, nil, nil, fmt.Errorf("%w: missing `sops` metadata section in %s", ErrInvalidFormat, path)
	}
	var meta sopsMetadata
	if err := sopsNode.Decode(&meta); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: decode `sops` metadata: %v", ErrInvalidFormat, err)
	}
	if len(meta.Age) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: no `sops.age` recipients found in %s", ErrInvalidFormat, path)
	}
	return &doc, root, &meta, nil
}

func findMapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func collectLeafKeys(node *yaml.Node, prefix string, out *[]KeyInfo) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k := node.Content[i].Value
			if prefix == "" && k == "sops" {
				continue
			}
			v := node.Content[i+1]
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			if err := collectLeafKeys(v, path, out); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if prefix != "" {
			*out = append(*out, KeyInfo{
				Path:        prefix,
				IsEncrypted: node.Tag == "!!str" && isEncryptedString(node.Value),
			})
		}
	case yaml.SequenceNode:
		// Sequences are treated as leaf paths when queried or skipped for scalar key listing.
		if prefix != "" {
			*out = append(*out, KeyInfo{
				Path:        prefix,
				IsEncrypted: false,
			})
		}
	}
	return nil
}

// InspectFile reads SOPS structural metadata and leaf key paths without touching any private key.
func InspectFile(path string) (*FileMeta, error) {
	_, root, meta, err := parseYAMLDocument(path)
	if err != nil {
		return nil, err
	}
	var keys []KeyInfo
	if err := collectLeafKeys(root, "", &keys); err != nil {
		return nil, err
	}
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k.Path] = true
	}
	recipients := make([]string, 0, len(meta.Age))
	seenRec := make(map[string]bool, len(meta.Age))
	for _, a := range meta.Age {
		r := strings.TrimSpace(a.Recipient)
		if r != "" && !seenRec[r] {
			seenRec[r] = true
			recipients = append(recipients, r)
		}
	}
	return &FileMeta{
		Recipients:       recipients,
		Keys:             keys,
		KeySet:           keySet,
		LastModified:     meta.LastModified,
		MAC:              meta.MAC,
		MACOnlyEncrypted: meta.MACOnlyEncrypted,
	}, nil
}

// ValidateKeyPath verifies a dot-separated key path is well-formed and does not target `sops`.
func ValidateKeyPath(keyPath string) ([]string, error) {
	keyPath = strings.TrimSpace(keyPath)
	if keyPath == "" {
		return nil, fmt.Errorf("%w: key path cannot be empty", ErrInvalidFormat)
	}
	parts := strings.Split(keyPath, ".")
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("%w: invalid key path %q (empty segment)", ErrInvalidFormat, keyPath)
		}
	}
	if parts[0] == "sops" {
		return nil, fmt.Errorf("%w: cannot target reserved `sops` metadata key", ErrInvalidFormat)
	}
	return parts, nil
}

type decryptedLeaf struct {
	Path        string
	Value       []byte
	MACChunk    []byte
	IsEncrypted bool
}

func decryptAndCollect(node *yaml.Node, dotPrefix, aadPrefix string, dataKey []byte, out *[]decryptedLeaf) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k := node.Content[i].Value
			if dotPrefix == "" && k == "sops" {
				continue
			}
			v := node.Content[i+1]
			nextDot := k
			if dotPrefix != "" {
				nextDot = dotPrefix + "." + k
			}
			nextAAD := aadPrefix + k + ":"
			if err := decryptAndCollect(v, nextDot, nextAAD, dataKey, out); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for idx, item := range node.Content {
			// SOPS AAD does not include array indices.
			nextDot := fmt.Sprintf("%s[%d]", dotPrefix, idx)
			if err := decryptAndCollect(item, nextDot, aadPrefix, dataKey, out); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			return nil
		}
		if node.Tag == "!!str" && isEncryptedString(node.Value) {
			plain, valType, err := decryptAESGCM(node.Value, dataKey, []byte(aadPrefix))
			if err != nil {
				return fmt.Errorf("%w: key %q: %v", ErrDecrypt, dotPrefix, err)
			}
			macChunk, err := sopsMACBytes(plain, valType)
			if err != nil {
				clear(plain)
				return err
			}
			exposed := normalizeExposedValue(plain, valType)
			if len(exposed) != len(plain) || (len(exposed) > 0 && &exposed[0] != &plain[0]) {
				clear(plain)
			}
			*out = append(*out, decryptedLeaf{
				Path:        dotPrefix,
				Value:       exposed,
				MACChunk:    macChunk,
				IsEncrypted: true,
			})
			return nil
		}
		// Unencrypted scalar leaf
		valType := yamlTagToSopsType(node.Tag)
		raw := []byte(node.Value)
		macChunk, err := sopsMACBytes(raw, valType)
		if err != nil {
			return err
		}
		*out = append(*out, decryptedLeaf{
			Path:        dotPrefix,
			Value:       raw,
			MACChunk:    macChunk,
			IsEncrypted: false,
		})
	}
	return nil
}

func yamlTagToSopsType(tag string) string {
	switch tag {
	case "!!int":
		return "int"
	case "!!float":
		return "float"
	case "!!bool":
		return "bool"
	default:
		return "str"
	}
}

func verifyMAC(meta *sopsMetadata, leaves []decryptedLeaf, dataKey []byte) error {
	if strings.TrimSpace(meta.MAC) == "" {
		return fmt.Errorf("%w: missing sops.mac", ErrDecrypt)
	}
	macBytes, _, err := decryptAESGCM(meta.MAC, dataKey, []byte(meta.LastModified))
	if err != nil {
		return fmt.Errorf("%w: decrypt sops.mac: %v", ErrDecrypt, err)
	}
	defer clear(macBytes)

	chunks := make([][]byte, 0, len(leaves))
	for _, lf := range leaves {
		if meta.MACOnlyEncrypted && !lf.IsEncrypted {
			continue
		}
		chunks = append(chunks, lf.MACChunk)
	}
	computed := computeSHA512Hex(chunks)
	if subtle.ConstantTimeCompare([]byte(strings.ToUpper(string(macBytes))), []byte(computed)) != 1 {
		return fmt.Errorf("%w: sops.mac integrity verification failed", ErrDecrypt)
	}
	return nil
}

// Decrypt decrypts a SOPS YAML file using ageKey, verifies full-file MAC, and returns the requested keys (or all leaf keys if selectedKeys is empty).
// Callers must wipe returned KV slices with WipeKVs.
func Decrypt(path string, ageKey []byte, selectedKeys []string) ([]KV, error) {
	_, root, meta, err := parseYAMLDocument(path)
	if err != nil {
		return nil, err
	}
	identity, err := ParseAgeIdentity(ageKey)
	if err != nil {
		return nil, err
	}
	dataKey, err := decryptDataKeyAge(meta.Age, identity)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)

	var leaves []decryptedLeaf
	if err := decryptAndCollect(root, "", "", dataKey, &leaves); err != nil {
		wipeLeaves(leaves)
		return nil, err
	}
	defer wipeLeaves(leaves)

	if err := verifyMAC(meta, leaves, dataKey); err != nil {
		return nil, err
	}

	if len(selectedKeys) == 0 {
		out := make([]KV, 0, len(leaves))
		for _, lf := range leaves {
			valCopy := make([]byte, len(lf.Value))
			copy(valCopy, lf.Value)
			out = append(out, KV{Key: lf.Path, Value: valCopy})
		}
		return out, nil
	}

	byPath := make(map[string]decryptedLeaf, len(leaves))
	for _, lf := range leaves {
		byPath[lf.Path] = lf
	}
	out := make([]KV, 0, len(selectedKeys))
	for _, k := range selectedKeys {
		lf, ok := byPath[k]
		if !ok {
			WipeKVs(out)
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, k)
		}
		valCopy := make([]byte, len(lf.Value))
		copy(valCopy, lf.Value)
		out = append(out, KV{Key: k, Value: valCopy})
	}
	return out, nil
}

func wipeLeaves(leaves []decryptedLeaf) {
	for i := range leaves {
		clear(leaves[i].Value)
		clear(leaves[i].MACChunk)
		leaves[i].Value = nil
		leaves[i].MACChunk = nil
	}
}

// InitFile creates a brand-new encrypted SOPS YAML file for the given age1... recipient(s).
// Fails if path already exists. Only requires public key(s).
func InitFile(path string, recipients []string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("%w: at least one age recipient is required", ErrInvalidFormat)
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: file already exists: %s", ErrInvalidFormat, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	dataKey := make([]byte, dataKeySize)
	if _, err := rand.Read(dataKey); err != nil {
		return fmt.Errorf("generate data key: %w", err)
	}
	defer clear(dataKey)

	ageEntries := make([]ageKeyEntry, 0, len(recipients))
	for _, r := range recipients {
		r = strings.TrimSpace(r)
		if err := ValidateRecipient(r); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidFormat, err)
		}
		enc, err := encryptDataKeyAge(dataKey, r)
		if err != nil {
			return err
		}
		ageEntries = append(ageEntries, ageKeyEntry{
			Recipient: r,
			Enc:       enc,
		})
	}

	lastModified := time.Now().UTC().Format(time.RFC3339)
	emptyHash := computeSHA512Hex(nil)
	macEnc, err := encryptAESGCM([]byte(emptyHash), dataKey, []byte(lastModified), "str")
	if err != nil {
		return fmt.Errorf("encrypt MAC: %w", err)
	}

	meta := sopsMetadata{
		Age:          ageEntries,
		LastModified: lastModified,
		MAC:          macEnc,
		Version:      sopsVersion,
	}

	root := &yaml.Node{Kind: yaml.MappingNode}
	var sopsVal yaml.Node
	if err := sopsVal.Encode(&meta); err != nil {
		return fmt.Errorf("encode sops metadata: %w", err)
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "sops"},
		&sopsVal,
	)

	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
	return writeYAMLAtomic(path, doc, true)
}

// SetKeys decrypts the existing Data Key, verifies existing MAC, upserts updates preserving untouched fields' ciphertext/IV, recomputes MAC, and atomically writes back.
func SetKeys(path string, ageKey []byte, updates []KV) error {
	if len(updates) == 0 {
		return fmt.Errorf("%w: no keys to set", ErrInvalidFormat)
	}
	for _, u := range updates {
		if _, err := ValidateKeyPath(u.Key); err != nil {
			return err
		}
	}

	doc, root, meta, err := parseYAMLDocument(path)
	if err != nil {
		return err
	}
	identity, err := ParseAgeIdentity(ageKey)
	if err != nil {
		return err
	}
	dataKey, err := decryptDataKeyAge(meta.Age, identity)
	if err != nil {
		return err
	}
	defer clear(dataKey)

	// Verify existing file integrity before mutating.
	var existingLeaves []decryptedLeaf
	if err := decryptAndCollect(root, "", "", dataKey, &existingLeaves); err != nil {
		wipeLeaves(existingLeaves)
		return err
	}
	if err := verifyMAC(meta, existingLeaves, dataKey); err != nil {
		wipeLeaves(existingLeaves)
		return err
	}
	wipeLeaves(existingLeaves)

	for _, u := range updates {
		parts, _ := ValidateKeyPath(u.Key)
		aad := strings.Join(parts, ":") + ":"
		encVal, err := encryptAESGCM(u.Value, dataKey, []byte(aad), "str")
		if err != nil {
			return fmt.Errorf("encrypt key %q: %w", u.Key, err)
		}
		if err := setMappingPath(root, parts, encVal); err != nil {
			return err
		}
	}

	return recomputeMACAndSave(path, doc, root, meta, dataKey)
}

// UnsetKeys deletes one or more leaf key paths, recomputes MAC, and atomically writes back.
func UnsetKeys(path string, ageKey []byte, keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("%w: no keys to unset", ErrInvalidFormat)
	}
	parsedPaths := make([][]string, 0, len(keys))
	for _, k := range keys {
		p, err := ValidateKeyPath(k)
		if err != nil {
			return err
		}
		parsedPaths = append(parsedPaths, p)
	}

	doc, root, meta, err := parseYAMLDocument(path)
	if err != nil {
		return err
	}
	identity, err := ParseAgeIdentity(ageKey)
	if err != nil {
		return err
	}
	dataKey, err := decryptDataKeyAge(meta.Age, identity)
	if err != nil {
		return err
	}
	defer clear(dataKey)

	var existingLeaves []decryptedLeaf
	if err := decryptAndCollect(root, "", "", dataKey, &existingLeaves); err != nil {
		wipeLeaves(existingLeaves)
		return err
	}
	if err := verifyMAC(meta, existingLeaves, dataKey); err != nil {
		wipeLeaves(existingLeaves)
		return err
	}
	wipeLeaves(existingLeaves)

	for idx, parts := range parsedPaths {
		removed, err := deleteMappingPath(root, parts)
		if err != nil {
			return err
		}
		if !removed {
			return fmt.Errorf("%w: %s", ErrKeyNotFound, keys[idx])
		}
	}

	return recomputeMACAndSave(path, doc, root, meta, dataKey)
}

func setMappingPath(root *yaml.Node, parts []string, encValue string) error {
	cur := root
	for i := 0; i < len(parts)-1; i++ {
		seg := parts[i]
		child := findMapValue(cur, seg)
		if child == nil {
			newMap := &yaml.Node{Kind: yaml.MappingNode}
			insertBeforeSops(cur, seg, newMap)
			cur = newMap
		} else if child.Kind == yaml.MappingNode {
			cur = child
		} else {
			return fmt.Errorf("%w: cannot traverse non-mapping segment %q", ErrInvalidFormat, seg)
		}
	}

	leafKey := parts[len(parts)-1]
	for i := 0; i+1 < len(cur.Content); i += 2 {
		if cur.Content[i].Value == leafKey {
			if cur.Content[i+1].Kind == yaml.MappingNode {
				return fmt.Errorf("%w: cannot overwrite mapping %q with scalar value", ErrInvalidFormat, strings.Join(parts, "."))
			}
			cur.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: encValue}
			return nil
		}
	}
	insertBeforeSops(cur, leafKey, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: encValue})
	return nil
}

// insertBeforeSops inserts a key/value pair into a mapping node, keeping `sops` as the final top-level key.
func insertBeforeSops(m *yaml.Node, key string, val *yaml.Node) {
	kNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "sops" {
			tail := make([]*yaml.Node, len(m.Content)-i)
			copy(tail, m.Content[i:])
			m.Content = append(m.Content[:i], kNode, val)
			m.Content = append(m.Content, tail...)
			return
		}
	}
	m.Content = append(m.Content, kNode, val)
}

func deleteMappingPath(m *yaml.Node, parts []string) (bool, error) {
	if m.Kind != yaml.MappingNode {
		return false, nil
	}
	seg := parts[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != seg {
			continue
		}
		if len(parts) == 1 {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true, nil
		}
		removed, err := deleteMappingPath(m.Content[i+1], parts[1:])
		if err != nil {
			return false, err
		}
		if removed && m.Content[i+1].Kind == yaml.MappingNode && len(m.Content[i+1].Content) == 0 {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
		}
		return removed, nil
	}
	return false, nil
}

func recomputeMACAndSave(path string, doc, root *yaml.Node, meta *sopsMetadata, dataKey []byte) error {
	var newLeaves []decryptedLeaf
	if err := decryptAndCollect(root, "", "", dataKey, &newLeaves); err != nil {
		wipeLeaves(newLeaves)
		return err
	}
	defer wipeLeaves(newLeaves)

	chunks := make([][]byte, 0, len(newLeaves))
	for _, lf := range newLeaves {
		if meta.MACOnlyEncrypted && !lf.IsEncrypted {
			continue
		}
		chunks = append(chunks, lf.MACChunk)
	}
	newLastMod := time.Now().UTC().Format(time.RFC3339)
	macHash := computeSHA512Hex(chunks)
	macEnc, err := encryptAESGCM([]byte(macHash), dataKey, []byte(newLastMod), "str")
	if err != nil {
		return fmt.Errorf("encrypt new sops.mac: %w", err)
	}

	sopsNode := findMapValue(root, "sops")
	if sopsNode == nil || sopsNode.Kind != yaml.MappingNode {
		return fmt.Errorf("%w: missing sops metadata node", ErrInvalidFormat)
	}
	setOrAddScalar(sopsNode, "lastmodified", newLastMod)
	setOrAddScalar(sopsNode, "mac", macEnc)

	return writeYAMLAtomic(path, doc, false)
}

func setOrAddScalar(m *yaml.Node, key, val string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val}
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
	)
}

func writeYAMLAtomic(path string, doc *yaml.Node, exclusive bool) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(4)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close YAML encoder: %w", err)
	}
	data := buf.Bytes()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if exclusive {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return fmt.Errorf("write %s: %w", path, err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return fmt.Errorf("sync %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(path)
			return fmt.Errorf("close %s: %w", path, err)
		}
		return os.Chmod(path, 0o600)
	}

	tmp, err := os.CreateTemp(dir, ".outsider-sops-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomic rename %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// FormatMultiKey serializes decrypted KV pairs for --file / --file-env handoff.
// Supported formats: "dotenv", "yaml", "json".
func FormatMultiKey(kvs []KV, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "dotenv":
		var buf bytes.Buffer
		for _, kv := range kvs {
			if !IsValidEnvName(kv.Key) {
				return nil, fmt.Errorf("key %q is not a valid dotenv/env identifier; use --file-format yaml or json", kv.Key)
			}
			buf.WriteString(kv.Key)
			buf.WriteByte('=')
			buf.WriteString(formatDotenvValue(string(kv.Value)))
			buf.WriteByte('\n')
		}
		return buf.Bytes(), nil
	case "yaml":
		tree := buildNestedMap(kvs)
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(tree); err != nil {
			return nil, fmt.Errorf("marshal yaml: %w", err)
		}
		_ = enc.Close()
		return buf.Bytes(), nil
	case "json":
		tree := buildNestedMap(kvs)
		out, err := json.MarshalIndent(tree, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal json: %w", err)
		}
		return append(out, '\n'), nil
	default:
		return nil, fmt.Errorf("unsupported --file-format %q (expected dotenv, yaml, or json)", format)
	}
}

func formatDotenvValue(v string) string {
	needsQuote := v == "" || strings.ContainsAny(v, " \t\r\n\"'\\#$")
	if !needsQuote {
		return v
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '$':
			b.WriteString(`\$`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func buildNestedMap(kvs []KV) map[string]any {
	root := make(map[string]any)
	for _, kv := range kvs {
		parts := strings.Split(kv.Key, ".")
		cur := root
		for i := 0; i < len(parts)-1; i++ {
			next, ok := cur[parts[i]].(map[string]any)
			if !ok {
				next = make(map[string]any)
				cur[parts[i]] = next
			}
			cur = next
		}
		cur[parts[len(parts)-1]] = string(kv.Value)
	}
	return root
}
