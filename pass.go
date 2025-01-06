package pkpass

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"net/http"

	"github.com/globe-protocol/util-package"
)

// Constants for error messages
const (
	pkpassCreationError = "failed to create pass"
)

// New creates a new Apple pass using a temporary directory for intermediate files.
// It ensures that temporary files are cleaned up after the pass is generated.
// Parameters:
//   - storageFolder: the root storage folder containing wwdr, template folder, and private_key.p12.
//   - passID: an identifier for the pass (used for reading content from passDir).
//   - password: the password for unlocking the .p12 certificate.
//   - cert: an io.Reader providing the .p12 certificate data.
func New(storageFolder, passFolder, passID, password string, cert io.Reader) (io.Reader, error) {
	// Create a temporary directory inside the storage folder
	tempDir := filepath.Join(storageFolder, "temp", fmt.Sprintf("pass-%s", passID))
	err := os.MkdirAll(tempDir, os.ModePerm)
	if err != nil {
		return nil, util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	// Ensure the temporary directory is removed after function completes
	defer os.RemoveAll(tempDir)

	// Paths for temporary files
	certFile := filepath.Join(tempDir, "certificates.p12")

	// Write the .p12 certificate to the temporary directory
	if err := writeFile(certFile, cert); err != nil {
		return nil, err
	}

	// Extract key and cert from p12
	if err = pem(tempDir, password); err != nil {
		return nil, err
	}
	if err = key(tempDir, password); err != nil {
		return nil, err
	}

	// Create a zip buffer
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	defer w.Close()

	// Bundle files from the passID directory within storageFolder
	if err = bundle(w, passFolder, tempDir); err != nil {
		return nil, err
	}

	// Sign the manifest
	wwdrCertPath := filepath.Join(storageFolder, "wwdr.pem")
	if err = sign(w, tempDir, password, wwdrCertPath); err != nil {
		return nil, err
	}

	return buf, nil
}

// writeFile writes data from an io.Reader to a specified file path.
func writeFile(path string, r io.Reader) error {
	file, err := os.Create(path)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	defer file.Close()

	if _, err := io.Copy(file, r); err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	return nil
}

// key extracts the private key from the .p12 certificate.
func key(storageFolder, password string) error {
	// check if it already exists
	if _, err := os.Stat(filepath.Join(storageFolder, "key.pem")); err == nil {
		return nil
	}

	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", filepath.Join(storageFolder, "certificates.p12"),
		"-nocerts",
		"-out", filepath.Join(storageFolder, "key.pem"),
		"-passin", fmt.Sprintf("pass:%s", password),
		"-passout", fmt.Sprintf("pass:%s1234", password),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(
			http.StatusInternalServerError,
			fmt.Errorf("failed to execute key extraction: %v, output: %s", err, output),
			pkpassCreationError,
		)
	}
	return nil
}

// pem extracts the certificate from the .p12 file.
func pem(storageFolder, password string) error {
	// check if it already exists
	if _, err := os.Stat(filepath.Join(storageFolder, "certificate.pem")); err == nil {
		return nil
	}

	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", filepath.Join(storageFolder, "certificates.p12"),
		"-clcerts",
		"-nokeys",
		"-out", filepath.Join(storageFolder, "certificate.pem"),
		"-passin", fmt.Sprintf("pass:%s", password),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(
			http.StatusInternalServerError,
			fmt.Errorf("failed to execute pem extraction: %v, output: %s", err, output),
			pkpassCreationError,
		)
	}
	return nil
}

func ensureFileExists(filePath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filePath); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("file not available: %s", filePath)
}

// bundle adds files from the pass directory to the zip writer and creates the manifest.json.
func bundle(w *zip.Writer, passDir, tempDir string) error {
	entries, err := os.ReadDir(passDir)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	manifest := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(passDir, entry.Name())
		if err := addFileToZip(w, filePath, entry.Name(), manifest); err != nil {
			return err
		}
	}

	for time.Now().Before(time.Now().Add(2 * time.Second)) {
		if _, err := os.Stat(filepath.Join(tempDir, "manifest.json")); err == nil {
			break
		}
	}

	// Create and add manifest.json to the zip
	manifestPath := filepath.Join(tempDir, "manifest.json")
	if err := createManifest(manifestPath, manifest); err != nil {
		return err
	}

	if err := ensureFileExists(manifestPath, 5*time.Second); err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)

	}

	// Add manifest.json to the zip
	if err := addFileToZip(w, manifestPath, "manifest.json", nil); err != nil {
		return err
	}

	return nil
}

// addFileToZip adds a single file to the zip and updates the manifest map.
func addFileToZip(w *zip.Writer, filePath, destFileName string, manifest map[string]string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	defer file.Close()

	hw := sha1.New()
	zw, err := w.Create(destFileName)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	var mw io.Writer = zw
	if manifest != nil {
		mw = io.MultiWriter(hw, zw)
	}

	if _, err = io.Copy(mw, file); err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	if manifest != nil {
		sha := hw.Sum(nil)
		manifest[destFileName] = fmt.Sprintf("%x", sha)
	}

	return nil
}

// createManifest creates the manifest.json file.
func createManifest(manifestPath string, manifest map[string]string) error {
	mf, err := os.Create(manifestPath)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	defer mf.Close()

	if err := json.NewEncoder(mf).Encode(manifest); err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	return nil
}

// sign signs the manifest and adds the signature to the zip.
func sign(w *zip.Writer, tempDir, password, wwdrCertPath string) error {
	cmd := exec.Command(
		"openssl",
		"smime",
		"-sign",
		"-signer", filepath.Join(tempDir, "certificate.pem"),
		"-inkey", filepath.Join(tempDir, "key.pem"),
		"-certfile", wwdrCertPath,
		"-in", filepath.Join(tempDir, "manifest.json"),
		"-out", filepath.Join(tempDir, "signature"),
		"-outform", "der",
		"-binary",
		"-passin", fmt.Sprintf("pass:%s1234", password),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(
			http.StatusInternalServerError,
			fmt.Errorf("failed to sign manifest: %v, output: %s", err, output),
			pkpassCreationError,
		)
	}

	// Add signature to the zip
	sigPath := filepath.Join(tempDir, "signature")
	if err := addFileToZip(w, sigPath, "signature", nil); err != nil {
		return err
	}

	return nil
}
