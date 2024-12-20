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
//   - passID: an identifier for the pass (used for reading content from passDir).
//   - password: the password for unlocking the .p12 certificate.
//   - cert: an io.Reader providing the .p12 certificate data.
func New(environment, workingDir, passID, password string, cert io.Reader) (io.Reader, error) {
	// get current working dir
	owWorkDir, err := os.Getwd()
	if err != nil {
		return nil, util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	// current
	workingDir = filepath.Join(owWorkDir, workingDir)
	// Copy certificate to file
	certFile := filepath.Join(workingDir, "certificates.p12")
	c, err := os.Create(certFile)
	if err != nil {
		return nil, util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	if environment != "local" {
		defer c.Close()
	}

	_, err = io.Copy(c, cert)
	if err != nil {
		return nil, util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	// Extract key and cert from p12
	if err = pem(workingDir, password); err != nil {
		return nil, err
	}
	if err = key(workingDir, password); err != nil {
		return nil, err
	}

	// Create zip buffer
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	defer w.Close()

	// Bundle files from the passID directory
	if err = bundle(w, workingDir); err != nil {
		return nil, err
	}

	// Sign the manifest
	if err = sign(w, workingDir, password, fmt.Sprintf("%s/wwdr.pem", workingDir)); err != nil {
		return nil, err
	}

	return buf, nil
}

func key(workingDir, password string) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", filepath.Join(workingDir, "certificates.p12"),
		"-nocerts",
		"-out", filepath.Join(workingDir, "key.pem"),
		"-passin", fmt.Sprintf("pass:%s", password),
		"-passout", fmt.Sprintf("pass:%s1234", password),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, fmt.Errorf("failed to execute command with dir: %s, error: %s, and output: %s", workingDir, err.Error(), output), pkpassCreationError)
	}

	return nil
}

func pem(workingDir, password string) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", filepath.Join(workingDir, "certificates.p12"),
		"-clcerts",
		"-nokeys",
		"-out", filepath.Join(workingDir, "certificate.pem"),
		"-passin", fmt.Sprintf("pass:%s", password),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, fmt.Errorf("failed to execute command with dir: %s, error: %s, and output: %s", workingDir, err.Error(), output), pkpassCreationError)
	}

	return nil
}

func bundle(w *zip.Writer, workingDir string) error {
	files, err := ioutil.ReadDir(workingDir)
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, err, pkpassCreationError)
	}

	// The rest of the code stays the same, just replace passDir with workingDir.
	m := make(map[string]string)
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}

		f, err := os.Open(filepath.Join(workingDir, fi.Name()))
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

	manifestPath := filepath.Join(workingDir, "manifest.json")
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

func sign(w *zip.Writer, workingDir, password, wwdrCertPath string) error {
	cmd := exec.Command(
		"openssl",
		"smime",
		"-sign",
		"-signer", filepath.Join(workingDir, "certificate.pem"),
		"-inkey", filepath.Join(workingDir, "key.pem"),
		"-certfile", wwdrCertPath,
		"-in", filepath.Join(workingDir, "manifest.json"),
		"-out", filepath.Join(workingDir, "signature"),
		"-outform", "der",
		"-binary",
		"-passin", fmt.Sprintf("pass:%s1234", password),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return util.NewErrorf(http.StatusInternalServerError, fmt.Errorf("failed with err: %s and output: %s", err.Error(), output), pkpassCreationError)
	}

	sig, err := os.Open(filepath.Join(workingDir, "signature"))
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
