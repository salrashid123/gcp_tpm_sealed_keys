package main

import (
	"flag"
	"io/ioutil"

	"crypto/sha256"
	"encoding/base64"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	tpmPath      = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	keyFile      = flag.String("keyFile", "", "Key File")
	bindPCRValue = flag.Int("bindPCRValue", -1, "PCR Value to bind session to")
)

func main() {

	flag.Parse()
	glog.V(2).Infof("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(2).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	glog.V(2).Infof("%d handles flushed\n", totalHandles)

	glog.V(10).Infof("======= Loading Key Handle ========")
	keyBytes, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		glog.Fatalf("ContextLoad failed for ekh: %v", err)
	}
	var kh tpmutil.Handle
	kh, err = tpm2.ContextLoad(rwc, keyBytes)
	if err != nil {
		glog.Fatalf("ContextLoad failed for kh: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)

	glog.V(2).Infof("======= Signing Data with Key Handle ========")

	data := []byte("foobar")
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)

	session, _, err := tpm2.StartAuthSession(
		rwc,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ make([]byte, 32),
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ tpm2.AlgSHA256)
	if err != nil {
		glog.Fatalf("StartAuthSession failed: %v", err)
	}
	defer tpm2.FlushContext(rwc, session)

	var signed *tpm2.Signature

	if *bindPCRValue >= 0 && *bindPCRValue <= 23 {
		if err = tpm2.PolicyPCR(rwc, session, nil, tpm2.PCRSelection{tpm2.AlgSHA256, []int{*bindPCRValue}}); err != nil {
			glog.Fatalf("PolicyPCR failed: %v", err)
		}

		khDigest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, data, tpm2.HandleOwner)
		if err != nil {
			glog.Errorf("Hash failed unexpectedly: %v", err)
			return
		}

		glog.V(5).Infof("     TPM based Hash %s", base64.StdEncoding.EncodeToString(khDigest))

		signed, err = tpm2.SignWithSession(rwc, session, kh, "", d[:], khValidation, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			glog.Fatalf("google: Unable to Sign wit TPM: %v", err)
		}
	} else {
		khDigest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, data, tpm2.HandleOwner)
		if err != nil {
			glog.Errorf("Hash failed unexpectedly: %v", err)
			return
		}

		glog.V(5).Infof("     TPM based Hash %s", base64.StdEncoding.EncodeToString(khDigest))
		signed, err = tpm2.Sign(rwc, kh, "", d[:], khValidation, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			glog.Fatalf("google: Unable to Sign with TPM: %v", err)
			return
		}
	}

	sig := base64.StdEncoding.EncodeToString(signed.RSA.Signature)
	glog.V(2).Infof("Test Signature: %s", sig)

}
