package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"

	"io/ioutil"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const defaultRSAExponent = 1<<16 + 1

var handleNames = map[string][]tpm2.HandleType{
	"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    {tpm2.HandleTypeLoadedSession},
	"saved":     {tpm2.HandleTypeSavedSession},
	"transient": {tpm2.HandleTypeTransient},
}

var (
	tpmPath              = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	importSigningKeyFile = flag.String("importSigningKeyFile", "", "Path to the importSigningKeyFile blob).")
	keyHandleOutputFile  = flag.String("keyHandleOutputFile", "key.dat", "Filename to save the loaded keyHandle.")
	bindPCRValue         = flag.Int("bindPCRValue", -1, "PCR Value to bind session to")
	persistentHandle     = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	evict                = flag.Bool("evict", false, "Evict handles")
	flush                = flag.String("flush", "transient", "Flush contexts, must be oneof transient|saved|loaded|all")
)

func main() {
	flag.Parse()

	if *importSigningKeyFile == "" {
		glog.Fatalf("importSigningKeyFile must be set")
	}
	err := importSigningKey(*tpmPath, *importSigningKeyFile, *keyHandleOutputFile, *bindPCRValue)
	if err != nil {
		glog.Fatalf("Error createSigningKeyImportBlob: %v\n", err)
	}

}

func importSigningKey(tpmPath string, importSigningKeyFile string, keyHandleOutputFile string, bindPCRValue int) (retErr error) {
	glog.V(2).Infof("======= Init importSigningKey ========")

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		return fmt.Errorf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", retErr, tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			return fmt.Errorf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				return fmt.Errorf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(2).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	if bindPCRValue >= 0 && bindPCRValue <= 23 {
		glog.V(2).Infof("======= Print PCR  ========")
		pcr23, err := tpm2.ReadPCR(rwc, bindPCRValue, tpm2.AlgSHA256)
		if err != nil {
			glog.Fatalf("Unable to ReadPCR: %v", err)
		}
		glog.V(2).Infof("Using PCR: %i %s", bindPCRValue, hex.EncodeToString(pcr23))
	}
	glog.V(2).Infof("======= Loading EndorsementKeyRSA ========")
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		return fmt.Errorf("Unable to get EndorsementKeyRSA: %v", err)
	}
	defer ek.Close()

	glog.V(2).Infof("======= Loading sealedkey ========")
	importblob := &pb.ImportBlob{}
	importdata, err := ioutil.ReadFile(importSigningKeyFile)
	if err != nil {
		glog.Fatalf("error reading sealed.dat: ", err)
	}
	err = proto.Unmarshal(importdata, importblob)
	if err != nil {
		glog.Fatal("Unmarshal error: ", err)
	}

	glog.V(2).Infof("======= Loading ImportSigningKey ========")
	key, err := ek.ImportSigningKey(importblob)
	defer key.Close()
	if err != nil {
		glog.Fatalf("error ImportSigningKey: ", err)
	}

	// save to a persistent Handle
	pHandle := tpmutil.Handle(*persistentHandle)
	if *evict {
		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, pHandle, pHandle)
		if err != nil {
			glog.Fatalf("     Unable evict persistentHandle: %v ", err)
		}
	}
	err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, key.Handle(), pHandle)
	if err != nil {
		glog.Fatalf("     Unable to set persistentHandle: %v", err)
	}

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

	if bindPCRValue >= 0 && bindPCRValue <= 23 {
		if err = tpm2.PolicyPCR(rwc, session, nil, tpm2.PCRSelection{tpm2.AlgSHA256, []int{bindPCRValue}}); err != nil {
			glog.Fatalf("PolicyPCR failed: %v", err)
		}

		khDigest, khValidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, data, tpm2.HandleOwner)
		if err != nil {
			glog.Errorf("Hash failed unexpectedly: %v", err)
			return
		}

		glog.V(5).Infof("     TPM based Hash %s", base64.StdEncoding.EncodeToString(khDigest))

		signed, err = tpm2.SignWithSession(rwc, session, key.Handle(), "", d[:], khValidation, &tpm2.SigScheme{
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
		signed, err = tpm2.Sign(rwc, key.Handle(), "", d[:], khValidation, &tpm2.SigScheme{
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

	return nil

}
