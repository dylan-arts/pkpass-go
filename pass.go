package pkpass

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

// New creates a new Apple pass, using a randomly generated temporary directory.
func New(passID string, password string, cert io.Reader) (io.Reader, error) {
	// Create a unique temporary directory
	tempDir, err := os.MkdirTemp("/app/storage/tmp", "pass-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	// Copy certificate to file
	certFile := filepath.Join(tempDir, "certificates.p12")
	c, err := os.Create(certFile)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	_, err = io.Copy(c, cert)
	if err != nil {
		return nil, err
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

	// Bundle files from passID directory (could also be passed in or handled elsewhere)
	if err = bundle(w, passID, tempDir); err != nil {
		return nil, err
	}

	// Sign the manifest
	if err = sign(w, tempDir, password); err != nil {
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
	return err
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
	return err
}

func bundle(w *zip.Writer, passDir, tempDir string) error {
	files, err := ioutil.ReadDir(passDir)
	if err != nil {
		return err
	}

	m := make(map[string]string)
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}

		f, err := os.Open(filepath.Join(passDir, fi.Name()))
		if err != nil {
			return err
		}
		defer f.Close()

		hw := sha1.New()
		zw, err := w.Create(fi.Name())
		if err != nil {
			return err
		}

		mw := io.MultiWriter(hw, zw)
		if _, err = io.Copy(mw, f); err != nil {
			return err
		}

		sha := hw.Sum(nil)
		m[fi.Name()] = fmt.Sprintf("%x", sha)
	}

	// Write manifest.json
	manifestPath := filepath.Join(tempDir, "manifest.json")
	mf, err := os.Create(manifestPath)
	if err != nil {
		return err
	}
	defer mf.Close()

	zw, err := w.Create("manifest.json")
	if err != nil {
		return err
	}
	mw := io.MultiWriter(mf, zw)

	if err = json.NewEncoder(mw).Encode(m); err != nil {
		return err
	}

	return nil
}

func sign(w *zip.Writer, tempDir, password string) error {
	cmd := exec.Command(
		"openssl",
		"smime",
		"-sign",
		"-signer", filepath.Join(tempDir, "certificate.pem"),
		"-inkey", filepath.Join(tempDir, "key.pem"),
		"-certfile", "/app/storage/wwdr.pem",
		"-in", filepath.Join(tempDir, "manifest.json"),
		"-out", filepath.Join(tempDir, "signature"),
		"-outform", "der",
		"-binary",
		"-passin", fmt.Sprintf("pass:%s1234", password),
	)

	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	sig, err := os.Open(filepath.Join(tempDir, "signature"))
	if err != nil {
		return err
	}
	defer sig.Close()

	zw, err := w.Create("signature")
	if err != nil {
		return err
	}

	_, err = io.Copy(zw, sig)
	return err
}
