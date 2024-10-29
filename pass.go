package pkpass

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// New will create a new Apple pass given the directory of companion files, the
// password needed to open the certificate, and the certificate. You should read
// the returned reader into a file, this file is your Apple pass and can be opened
// from iOS and macOS devices.
func New(passID string, password string, cert io.Reader) (io.Reader, error) {
	log.Println("Starting pkpass creation")

	tempDir := fmt.Sprintf("/app/storage/tmp/%s", passID)
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		log.Printf("Error creating temp directory: %v", err)
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	// Copy certificate to file
	c, err := os.Create(fmt.Sprintf("%s/certificates.p12", tempDir))
	if err != nil {
		log.Printf("Error creating certificate file: %v", err)
		return nil, err
	}
	defer c.Close()

	_, err = io.Copy(c, cert)
	if err != nil {
		log.Printf("Error copying certificate: %v", err)
		return nil, err
	}

	log.Println("Certificate copied to temp directory")

	// Create certificate.pem
	err = pem(tempDir, password, cert)
	if err != nil {
		log.Printf("Error creating PEM file: %v", err)
		return nil, err
	}
	log.Println("PEM file created")

	// Create key.pem
	err = key(tempDir, password, cert)
	if err != nil {
		log.Printf("Error creating key PEM file: %v", err)
		return nil, err
	}
	log.Println("Key PEM file created")

	// Create zip buffer
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	defer w.Close()

	// Bundle the files
	err = bundle(w, passID, tempDir)
	if err != nil {
		log.Printf("Error bundling files: %v", err)
		return nil, err
	}
	log.Println("Files bundled successfully")

	// Sign the manifest
	err = sign(w, tempDir, password)
	if err != nil {
		log.Printf("Error signing the manifest: %v", err)
		return nil, err
	}
	log.Println("Manifest signed successfully")

	return buf, nil
}

func key(tempDir, password string, cert io.Reader) error {
	log.Println("Generating key.pem file")
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", fmt.Sprintf("%s/certificates.p12", tempDir),
		"-nocerts",
		"-out", fmt.Sprintf("%s/key.pem", tempDir),
		"-passin", fmt.Sprintf("pass:%s", password),
		"-passout", fmt.Sprintf("pass:%s1234", password),
	)

	output, err := cmd.CombinedOutput() // Capture both stdout and stderr
	if err != nil {
		log.Printf("Error running command: %v", err)
		log.Printf("Command output: %s", output)
		return err
	}
	log.Println("Key PEM file generated")
	return nil
}

func pem(tempDir, password string, cert io.Reader) error {
	log.Println("Generating certificate.pem file")
	cmd := exec.Command(
		"openssl",
		"pkcs12",
		"-in", fmt.Sprintf("%s/certificates.p12", tempDir),
		"-clcerts",
		"-nokeys",
		"-out", fmt.Sprintf("%s/certificate.pem", tempDir),
		"-passin", fmt.Sprintf("pass:%s", password),
	)

	output, err := cmd.CombinedOutput() // Capture both stdout and stderr
	if err != nil {
		log.Printf("Error running command: %v", err)
		log.Printf("Command output: %s", output)
		return err
	}
	log.Println("Certificate PEM file generated")
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
	log.Println("Signing the manifest")

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
	log.Printf("Running command: %v", cmd)
	output, err := cmd.CombinedOutput() // Capture both stdout and stderr
	if err != nil {
		log.Printf("Error running command: %v", err)
		log.Printf("Command output: %s", output)
		return err
	}
	log.Println("Manifest signed successfully")

	// Add signature to the zip
	sig, err := os.Open(fmt.Sprintf("%s/signature", tempDir))
	if err != nil {
		log.Printf("Error opening signature file: %v", err)
		return err
	}
	defer sig.Close()

	zw, err := w.Create("signature")
	if err != nil {
		log.Printf("Error creating signature file in zip: %v", err)
		return err
	}

	_, err = io.Copy(zw, sig)
	if err != nil {
		log.Printf("Error copying signature to zip: %v", err)
		return err
	}

	log.Println("Signature added to the zip")
	return nil
}
