package pkpass

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/globe-protocol/util-package"
)

const (
	pkpassCreationError = "failed to create pass"
)

// New creates a new Apple pass, using a randomly generated temporary directory.
// Parameters:
//   - workingDir: the base directory where temporary directories and files will be created.
//   - wwdrCertPath: the file path to the Apple WWDR certificate (e.g. "/path/to/wwdr.pem").
//   - passID: an identifier for the pass (used for reading content from passDir).
//   - password: the password for unlocking the .p12 certificate.
//   - cert: an io.Reader providing the .p12 certificate data.
func New(workingDir, passID, password string, cert io.Reader) (io.Reader, error) {
	// Create a unique temporary directory under the specified workingDir
	tempDir, err := os.MkdirTemp(workingDir, "pass-*")
	if err != nil {
		return nil, util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	defer os.RemoveAll(tempDir)

	// Copy certificate to file
	certFile := filepath.Join(tempDir, "certificates.p12")
	c, err := os.Create(certFile)
	if err != nil {
		return nil, util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	defer c.Close()

	_, err = io.Copy(c, cert)
	if err != nil {
		return nil, util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	// Extract key and cert from p12
	if err = pem(tempDir, password); err != nil {
		return nil, err
	}
	if err = key(tempDir, password); err != nil {
		return nil, err
	}

	// Create zip buffer
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	defer w.Close()

	// Bundle files from the passID directory
	if err = bundle(w, passID, tempDir); err != nil {
		return nil, err
	}

	// Sign the manifest
	if err = sign(w, tempDir, password, workingDir); err != nil {
		return nil, err
	}

	return buf, nil
}

func key(tempDir, password string) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", filepath.Join(tempDir, "certificates.p12"),
		"-nocerts",
		"-out", filepath.Join(tempDir, "key.pem"),
		"-passin", fmt.Sprintf("pass:%s", password),
		"-passout", fmt.Sprintf("pass:%s1234", password),
	)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, fmt.Errorf("failed to execute command with dir: %s and error: %s", tempDir, err.Error()), pkpassCreationError)
	}

	return nil
}

func pem(tempDir, password string) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", filepath.Join(tempDir, "certificates.p12"),
		"-clcerts",
		"-nokeys",
		"-out", filepath.Join(tempDir, "certificate.pem"),
		"-passin", fmt.Sprintf("pass:%s", password),
	)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, fmt.Errorf("failed to execute command with dir: %s and error: %s", tempDir, err.Error()), pkpassCreationError)
	}

	return nil
}

func bundle(w *zip.Writer, passDir, tempDir string) error {
	files, err := ioutil.ReadDir(passDir)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	m := make(map[string]string)
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}

		f, err := os.Open(filepath.Join(passDir, fi.Name()))
		if err != nil {
			return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
		}
		defer f.Close()

		hw := sha1.New()
		zw, err := w.Create(fi.Name())
		if err != nil {
			return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
		}

		mw := io.MultiWriter(hw, zw)
		if _, err = io.Copy(mw, f); err != nil {
			return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
		}

		sha := hw.Sum(nil)
		m[fi.Name()] = fmt.Sprintf("%x", sha)
	}

	// Write manifest.json
	manifestPath := filepath.Join(tempDir, "manifest.json")
	mf, err := os.Create(manifestPath)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	defer mf.Close()

	zw, err := w.Create("manifest.json")
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	mw := io.MultiWriter(mf, zw)

	if err = json.NewEncoder(mw).Encode(m); err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	return nil
}

func sign(w *zip.Writer, tempDir, password, wwdrCertPath string) error {
	cmd := exec.Command(
		"openssl",
		"smime",
		"-sign",
		"-signer", filepath.Join(tempDir, "certificate.pem"),
		"-inkey", filepath.Join(tempDir, "key.pem"),
		"-certfile", wwdrCertPath, // Use the provided WWDR certificate path
		"-in", filepath.Join(tempDir, "manifest.json"),
		"-out", filepath.Join(tempDir, "signature"),
		"-outform", "der",
		"-binary",
		"-passin", fmt.Sprintf("pass:%s1234", password),
	)

	_, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	sig, err := os.Open(filepath.Join(tempDir, "signature"))
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}
	defer sig.Close()

	zw, err := w.Create("signature")
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	_, err = io.Copy(zw, sig)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	return nil
}
