package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSealAndSealOpen(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := []byte("hello world")
	out, err := DefaultCryptoBox.Seal(SealInput{RecipientKey: pub[:], Message: msg})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := DefaultCryptoBox.SealOpen(SealOpenInput{RecipientKey: priv[:], Ciphertext: out.Encrypted})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened.Message, msg) {
		t.Fatalf("got %q want %q", opened.Message, msg)
	}
}

func TestSealOpenLibsodium(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	msg := []byte("interop test")
	out, err := DefaultCryptoBox.Seal(SealInput{RecipientKey: pub[:], Message: msg})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	script := "const sodium=require('libsodium-wrappers-sumo');" +
		"(async()=>{await sodium.ready;" +
		"const c=Buffer.from(process.argv[1],'hex');" +
		"const pk=Buffer.from(process.argv[2],'hex');" +
		"const sk=Buffer.from(process.argv[3],'hex');" +
		"const m=sodium.crypto_box_seal_open(c,pk,sk);" +
		"console.log(Buffer.from(m).toString('hex'));})();"
	cmd := exec.Command("node", "-e", script, hex.EncodeToString(out.Encrypted), hex.EncodeToString(pub[:]), hex.EncodeToString(priv[:]))
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		// attempt to install dependency and retry once
		if bytes.Contains(outBytes, []byte("Cannot find module")) {
			install := exec.Command("npm", "install", "libsodium-wrappers-sumo")
			if instOut, instErr := install.CombinedOutput(); instErr != nil {
				t.Fatalf("npm install failed: %v\n%s", instErr, string(instOut))
			}
			cmd = exec.Command("node", "-e", script, hex.EncodeToString(out.Encrypted), hex.EncodeToString(pub[:]), hex.EncodeToString(priv[:]))
			outBytes, err = cmd.CombinedOutput()
		}
		if err != nil {
			t.Fatalf("node exec failed: %v\n%s", err, string(outBytes))
		}
	}
	decoded, err := hex.DecodeString(string(bytes.TrimSpace(outBytes)))
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if !bytes.Equal(decoded, msg) {
		t.Fatalf("libsodium decrypted %q want %q", decoded, msg)
	}
}
