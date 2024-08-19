// Package bundle implements support for unified runtime bundles.
package bundle

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/sigstruct"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

// Bundle is a runtime bundle instance.
type Bundle struct {
	Manifest *Manifest
	Data     map[string][]byte

	// manifestHash is the original manifest hash of the bundle at time the bundle was loaded.
	manifestHash hash.Hash
}

// Validate validates the runtime bundle for well-formedness.
func (bnd *Bundle) Validate() error {
	// Ensure the manifest is valid.
	if err := bnd.Manifest.Validate(); err != nil {
		return fmt.Errorf("runtime/bundle: malformed manifest: %w", err)
	}

	// Ensure all the files in the manifest are present.
	type bundleFile struct {
		descr, fn string
		optional  bool
	}
	var needFiles []bundleFile
	for id, comp := range bnd.Manifest.GetAvailableComponents() {
		needFiles = append(needFiles, bundleFile{
			descr: fmt.Sprintf("%s: ELF executable", id),
			fn:    comp.Executable,
		})
		if sgx := comp.SGX; sgx != nil {
			needFiles = append(needFiles,
				[]bundleFile{
					{
						descr: fmt.Sprintf("%s: SGX executable", id),
						fn:    sgx.Executable,
					},
					{
						descr:    fmt.Sprintf("%s: SGX signature", id),
						fn:       sgx.Signature,
						optional: true,
					},
				}...,
			)
		}
	}
	for _, v := range needFiles {
		if v.fn == "" {
			if v.optional {
				continue
			}
			return fmt.Errorf("runtime/bundle: missing %s in manifest", v.descr)
		}
		if len(bnd.Data[v.fn]) == 0 {
			return fmt.Errorf("runtime/bundle: missing %s in bundle", v.descr)
		}
	}

	// Ensure all files in the bundle have a digest entry, and that the
	// extracted file's digest matches the one in the manifest.
	for fn, b := range bnd.Data {
		h := hash.NewFromBytes(b)

		mh, ok := bnd.Manifest.Digests[fn]
		if !ok {
			// Ignore the manifest not having a digest entry, though
			// it having one and being valid (while quite a feat) is
			// also ok.
			if fn == manifestName {
				continue
			}
			return fmt.Errorf("runtime/bundle: missing digest: '%s'", fn)
		}
		if !h.Equal(&mh) {
			return fmt.Errorf("runtime/bundle: invalid digest: '%s'", fn)
		}
	}

	for id, comp := range bnd.Manifest.GetAvailableComponents() {
		// Make sure the ELF executable actually is an ELF image.
		f, err := elf.NewFile(bytes.NewReader(bnd.Data[comp.Executable]))
		if err != nil {
			return fmt.Errorf("runtime/bundle: ELF executable for component '%s' isnt: %w", id, err)
		}
		_ = f.Close()

		// Make sure the SGX signature is valid if it exists.
		if err = bnd.verifySgxSignature(comp); err != nil {
			return err
		}
	}

	return nil
}

// Add adds/overwrites a file to/in the bundle.
func (bnd *Bundle) Add(fn string, b []byte) error {
	if filepath.Dir(fn) != "." {
		return fmt.Errorf("runtime/bundle: invalid filename for add: '%s'", fn)
	}

	if bnd.Manifest.Digests == nil {
		bnd.Manifest.Digests = make(map[string]hash.Hash)
	}
	if bnd.Data == nil {
		bnd.Data = make(map[string][]byte)
	}

	h := hash.NewFromBytes(b)
	bnd.Manifest.Digests[fn] = h
	bnd.Data[fn] = append([]byte{}, b...) // Copy
	return nil
}

// MrEnclave returns the MRENCLAVE of the SGX excutable.
func (bnd *Bundle) MrEnclave(id component.ID) (*sgx.MrEnclave, error) {
	comp := bnd.Manifest.GetComponentByID(id)
	if comp == nil {
		return nil, fmt.Errorf("runtime/bundle: component '%s' not available", id)
	}
	if comp.SGX == nil {
		return nil, fmt.Errorf("runtime/bundle: no SGX metadata for '%s'", id)
	}
	d, ok := bnd.Data[comp.SGX.Executable]
	if !ok {
		return nil, fmt.Errorf("runtime/bundle: no SGX executable for '%s'", id)
	}

	var mrEnclave sgx.MrEnclave
	if err := mrEnclave.FromSgxs(bytes.NewReader(d)); err != nil {
		return nil, fmt.Errorf("runtime/bundle: failed to derive SGX MRENCLAVE for '%s': %w", id, err)
	}
	return &mrEnclave, nil
}

// MrSigner returns the MRSIGNER that signed the SGX executable.
func (bnd *Bundle) MrSigner(id component.ID) (*sgx.MrSigner, error) {
	comp := bnd.Manifest.GetComponentByID(id)
	if comp == nil {
		return nil, fmt.Errorf("runtime/bundle: component '%s' not available", id)
	}
	if comp.SGX == nil {
		return nil, fmt.Errorf("runtime/bundle: no SGX metadata for '%s'", id)
	}

	var mrSigner sgx.MrSigner
	switch {
	case comp.SGX.Signature == "" && cmdFlags.DebugDontBlameOasis():
		// Use dummy signer (only in tests).
		mrSigner = sgx.FortanixDummyMrSigner
	default:
		// Load the actual signature.
		sigPk, _, err := sigstruct.Verify(bnd.Data[comp.SGX.Signature])
		if err != nil {
			return nil, err
		}
		if err = mrSigner.FromPublicKey(sigPk); err != nil {
			return nil, err
		}
	}
	return &mrSigner, nil
}

// EnclaveIdentity returns the SGX enclave identity of the given component.
func (bnd *Bundle) EnclaveIdentity(id component.ID) (*sgx.EnclaveIdentity, error) {
	mrEnclave, err := bnd.MrEnclave(id)
	if err != nil {
		return nil, err
	}

	mrSigner, err := bnd.MrSigner(id)
	if err != nil {
		return nil, err
	}

	return &sgx.EnclaveIdentity{
		MrEnclave: *mrEnclave,
		MrSigner:  *mrSigner,
	}, nil
}

func (bnd *Bundle) verifySgxSignature(comp *Component) error {
	if comp.SGX == nil || comp.SGX.Signature == "" {
		return nil
	}

	mrEnclave, err := bnd.MrEnclave(comp.ID())
	if err != nil {
		return err
	}
	_, sigStruct, err := sigstruct.Verify(bnd.Data[comp.SGX.Signature])
	if err != nil {
		return fmt.Errorf("runtime/bundle: failed to verify sigstruct for '%s': %w", comp.Kind, err)
	}

	if sigStruct.EnclaveHash != *mrEnclave {
		return fmt.Errorf("runtime/bundle: sigstruct for '%s' does not match SGXS (got: %s expected: %s)", comp.Kind, sigStruct.EnclaveHash, *mrEnclave)
	}

	return nil
}

// ResetManifest removes the serialized manifest from the bundle so that it can be regenerated on
// the next call to Write.
//
// This needs to be used after doing modifications to bundles.
func (bnd *Bundle) ResetManifest() {
	delete(bnd.Data, manifestName)
}

// Write serializes a runtime bundle to the on-disk representation.
func (bnd *Bundle) Write(fn string) error {
	// Ensure the bundle is well-formed.
	if err := bnd.Validate(); err != nil {
		return fmt.Errorf("runtime/bundle: refusing to write malformed bundle: %w", err)
	}

	// Serialize the manifest.
	rawManifest, err := json.Marshal(bnd.Manifest)
	if err != nil {
		return fmt.Errorf("runtime/bundle: failed to serialize manifest: %w", err)
	}
	if bnd.Data[manifestName] != nil {
		// While this is "ok", instead of trying to figure out if the
		// deserialized manifest matches the serialied one, just bail.
		return fmt.Errorf("runtime/bundle: data contains manifest entry")
	}

	// Write out the archive to a in-memory buffer, taking care to ensure
	// that the manifest is the 0th entry.
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	type writeFile struct {
		fn string
		b  []byte
	}
	writeFiles := []writeFile{
		{
			fn: manifestName,
			b:  rawManifest,
		},
	}
	for f := range bnd.Data {
		writeFiles = append(writeFiles, writeFile{
			fn: f,
			b:  bnd.Data[f],
		})
	}
	for _, f := range writeFiles {
		fw, wErr := w.Create(f.fn)
		if wErr != nil {
			return fmt.Errorf("runtime/bundle: failed to create file '%s': %w", f.fn, wErr)
		}
		if _, wErr = fw.Write(f.b); err != nil {
			return fmt.Errorf("runtime/bundle: failed to write file '%s': %w", f.fn, wErr)
		}
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("runtime/bundle: failed to finalize bundle: %w", err)
	}

	if err = os.WriteFile(fn, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("runtime/bundle: failed to write bundle: %w", err)
	}

	// Update the manifest hash.
	bnd.manifestHash = bnd.Manifest.Hash()

	return nil
}

// ExplodedPath returns the path under the data directory that contains all of the exploded bundles.
func ExplodedPath(dataDir string) string {
	return filepath.Join(dataDir, "runtimes", "bundles")
}

// DetachedExplodedPath returns the path under the data directory that contains all of the detached
// exploded bundles.
func DetachedExplodedPath(dataDir string) string {
	return filepath.Join(ExplodedPath(dataDir), "detached")
}

// ExplodedPath returns the path that the corresponding asset will be written to via WriteExploded.
func (bnd *Bundle) ExplodedPath(dataDir, fn string) string {
	var subDir string
	switch bnd.Manifest.IsDetached() {
	case false:
		// DATADIR/runtimes/bundles/manifestHash
		subDir = filepath.Join(ExplodedPath(dataDir),
			bnd.manifestHash.String(),
		)
	case true:
		// DATADIR/runtimes/bundles/detached/manifestHash
		subDir = filepath.Join(DetachedExplodedPath(dataDir),
			bnd.manifestHash.String(),
		)
	}

	if fn == "" {
		return subDir
	}
	return filepath.Join(subDir, fn)
}

// WriteExploded writes the extracted runtime bundle to the appropriate
// location under the specified data directory.
func (bnd *Bundle) WriteExploded(dataDir string) error {
	if err := bnd.Validate(); err != nil {
		return fmt.Errorf("runtime/bundle: refusing to explode malformed bundle: %w", err)
	}

	subDir := bnd.ExplodedPath(dataDir, "")

	// Check to see if we have done this before, and be nice to SSDs by
	// just verifying extracted data for correctness.
	switch _, err := os.Stat(subDir); err {
	case nil:
		// Validate that the on-disk assets match the bundle contents.
		//
		// Note: This ignores extra garbage that may be on disk, but
		// people that mess with internal directories get what they
		// deserve.
		for fn, expected := range bnd.Data {
			fn = bnd.ExplodedPath(dataDir, fn)
			b, rdErr := os.ReadFile(fn)
			if rdErr != nil {
				return fmt.Errorf("runtime/bundle: failed to re-load asset '%s': %w", fn, rdErr)
			}
			if !bytes.Equal(b, expected) {
				return fmt.Errorf("runtime/bundle: corrupt asset: '%s'", fn)
			}
		}
	default:
		// Extract the bundle to disk.
		if !os.IsNotExist(err) {
			return fmt.Errorf("runtime/bundle: failed to stat asset directory '%s': %w", subDir, err)
		}

		for _, v := range []string{
			subDir,
			bnd.ExplodedPath(dataDir, manifestPath),
		} {
			if err = os.MkdirAll(v, 0o700); err != nil {
				return fmt.Errorf("runtime/bundle: failed to create asset sub-dir '%s': %w", v, err)
			}
		}
		for fn, data := range bnd.Data {
			fn = bnd.ExplodedPath(dataDir, fn)
			if err = os.WriteFile(fn, data, 0o600); err != nil {
				return fmt.Errorf("runtime/bundle: failed to write asset '%s': %w", fn, err)
			}
		}

		for id, comp := range bnd.Manifest.GetAvailableComponents() {
			if comp.Executable != "" {
				if err := os.Chmod(bnd.ExplodedPath(dataDir, comp.Executable), 0o700); err != nil {
					return fmt.Errorf("runtime/bundle: failed to fixup executable permissions for '%s': %w", id, err)
				}
			}
		}
	}

	return nil
}

// Close closes the bundle, releasing resources.
func (bnd *Bundle) Close() error {
	bnd.Manifest = nil
	bnd.Data = nil
	bnd.manifestHash.Empty()
	return nil
}

// Open opens and validates a runtime bundle instance.
func Open(fn string) (*Bundle, error) {
	r, err := zip.OpenReader(fn)
	if err != nil {
		return nil, fmt.Errorf("runtime/bundle: failed to open bundle: %w", err)
	}
	defer r.Close()

	// Read the contents.
	//
	// Note: This extracts everything into memory, which is somewhat
	// expensive if it turns out the contents aren't needed.
	data := make(map[string][]byte)
	for i, v := range r.File {
		// Sanitize the file name by ensuring that all names are rooted
		// at the correct location.
		switch i {
		case 0:
			// Much like the JAR files, the manifest MUST come first.
			if v.Name != manifestName {
				return nil, fmt.Errorf("runtime/bundle: invalid manifest file name: '%s'", v.Name)
			}
		default:
			if filepath.Dir(v.Name) != "." {
				return nil, fmt.Errorf("runtime/bundle: failed to sanitize path '%s'", v.Name)
			}
		}

		// Extract every file into memory.
		rd, rdErr := v.Open()
		if rdErr != nil {
			return nil, fmt.Errorf("runtime/bundle: failed to open '%s': %w", v.Name, rdErr)
		}
		defer rd.Close()

		b, rdErr := io.ReadAll(rd)
		if err != nil {
			return nil, fmt.Errorf("runtime/bundle: failed to read '%s': %w", v.Name, rdErr)
		}

		data[v.Name] = b
	}

	// Decode the manifest.
	var manifest Manifest
	b, ok := data[manifestName]
	if !ok {
		return nil, fmt.Errorf("runtime/bundle: missing manifest")
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		return nil, fmt.Errorf("runtime/bundle: failed to parse manifest: %w", err)
	}

	// Ensure the bundle is well-formed.
	bnd := &Bundle{
		Manifest:     &manifest,
		Data:         data,
		manifestHash: manifest.Hash(),
	}
	if err = bnd.Validate(); err != nil {
		return nil, err
	}

	return bnd, nil
}
