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

// New will create a new Apple pass given the directory of companion files, the
// password needed to open the certificate, and the certificate. You should read
// the returned reader into a file, this file is your Apple pass and can be opened
// from iOS and macOS devices.
func New(passID string, password string, cert io.Reader) (io.Reader, error) {
	tempDir := fmt.Sprintf("/app/storage/tmp/%s", passID)
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	// Copy certificate to file
	c, err := os.Create(fmt.Sprintf("%s/certificates.p12", tempDir))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	_, err = io.Copy(c, cert)
	if err != nil {
		return nil, err
	}

	// Create certificate.pem
	err = pem(tempDir, password)
	if err != nil {
		return nil, err
	}

	// Create key.pem
	err = key(tempDir, password)
	if err != nil {
		return nil, err
	}

	// Create zip buffer
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	defer w.Close()

	// Bundle the files
	err = bundle(w, passID, tempDir)
	if err != nil {
		return nil, err
	}

	// Sign the manifest
	err = sign(w, tempDir, password)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func key(tempDir, password string) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", fmt.Sprintf("%s/certificates.p12", tempDir),
		"-nocerts",
		"-out", fmt.Sprintf("%s/key.pem", tempDir),
		"-passin", fmt.Sprintf("pass:%s", password),
		"-passout", fmt.Sprintf("pass:%s1234", password),
	)

	_, err := cmd.CombinedOutput() // Capture both stdout and stderr
	if err != nil {
		return err
	}
	return nil
}

func pem(tempDir, password string) error {
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", fmt.Sprintf("%s/certificates.p12", tempDir),
		"-clcerts",
		"-nokeys",
		"-out", fmt.Sprintf("%s/certificate.pem", tempDir),
		"-passin", fmt.Sprintf("pass:%s", password),
	)

	_, err := cmd.CombinedOutput() // Capture both stdout and stderr
	if err != nil {
		return err
	}

	return nil
}

// bundle will read all of the files in the passDir, create a manifest.json, and
// add all files to the zip archive.
func bundle(w *zip.Writer, passDir, tempDir string) error {
	files, err := ioutil.ReadDir(passDir)
	if err != nil {
		return err
	}

	var m = make(map[string]string)
	for _, fi := range files {
		// Skip directories, they are meaningless in this situation
		if fi.IsDir() {
			continue
		}

		// Open the file in the directory
		f, err := os.Open(filepath.Join(passDir, fi.Name()))
		if err != nil {
			return err
		}

		// Create the sha writer
		hw := sha1.New()

		// Create the zip writer
		zw, err := w.Create(fi.Name())
		if err != nil {
			return err
		}

		mw := io.MultiWriter(hw, zw)

		// Write the file to the zip writer
		_, err = io.Copy(mw, f)
		if err != nil {
			return err
		}

		// Add the hash to a map, later we will json.Marshal this to make manifest.json
		sha := hw.Sum(nil)
		m[fi.Name()] = fmt.Sprintf("%x", sha)
	}

	// Create the file writer
	f, err := os.Create(filepath.Join(tempDir, "manifest.json"))
	if err != nil {
		return err
	}
	defer f.Close()

	// Create the zip writer
	zw, err := w.Create("manifest.json")
	if err != nil {
		return err
	}

	mw := io.MultiWriter(f, zw)

	// Write the JSON to the file, and zip
	err = json.NewEncoder(mw).Encode(m)
	if err != nil {
		return err
	}

	return nil
}

// sign will sign the manifest json using the keys and certificates created
// in key and pem respectively. It will then write the signature file to the zip
// archive so that we can open the pass.
func sign(w *zip.Writer, tempDir, password string) error {
	// Sign the bundle
	cmd := exec.Command(
		"openssl",
		"smime",
		"-sign",
		"-signer", fmt.Sprintf("%s/certificate.pem", tempDir),
		"-inkey", fmt.Sprintf("%s/key.pem", tempDir),
		"-certfile", "/app/storage/wwdr.pem",
		"-in", fmt.Sprintf("%s/manifest.json", tempDir),
		"-out", fmt.Sprintf("%s/signature", tempDir),
		"-outform", "der",
		"-binary",
		"-passin", fmt.Sprintf("pass:%s1234", password),
	)

	_, err := cmd.CombinedOutput() // Capture both stdout and stderr <- use _ output for debug
	if err != nil {
		return err
	}

	// Add signature to the zip
	sig, err := os.Open(fmt.Sprintf("%s/signature", tempDir))
	if err != nil {
		return err
	}
	defer sig.Close()

	zw, err := w.Create("signature")
	if err != nil {
		return err
	}

	_, err = io.Copy(zw, sig)
	if err != nil {
		return err
	}

	return nil
}
