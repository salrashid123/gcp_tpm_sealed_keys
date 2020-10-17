## Sealing RSA and Symmetric keys with GCP vTPMs

Sample applications that seal keys to [TPM](https://en.wikipedia.org/wiki/Trusted_Platform_Module) [Platform Configuration Registers (PCR)](https://link.springer.com/chapter/10.1007/978-1-4302-6584-9_12) values using Google [Confidential Compute](https://cloud.google.com/confidential-computing) instances

This repo demonstrates how a remote user can acquire a GCP VM's unique [Endorsement Public key](https://cloud.google.com/security/shielded-cloud/retrieving-endorsement-key) and then use that to seal/encrypt a key such that it can only get unsealed/decrypted _on that vm_.

In addition, the key is sealed using a PCR policy that mandates the key can only be unsealed or used if specific PCR values are present on that VM.
and if the VM gets deleted, the key cannot be unsealed.

There are two types of keys that are sealed and transferred
* Seals arbitrary symmetric key to a TPM
  An arbitrary key which can be a simple AES key or in the example below, just "hello world"

* Seals RSA Private key to TPM
  An RSA private key that is sealed and embedded into the TPM.  Note: once an RSA key is imported, the TPM will only use it to sign data.
  The raw embedded key will not get exported outside of the TPM.   

In the final step, we will alter/extend the PCR value we originally sealed data against.  This will prevent any further unsealing of the symmetric key as well as prevent import of the RSA key.  Furthermore, since we imported an RSA key with a different PCR value earlier, this will prevent using the TPM to sign  using that RSA key.


---

### Setup

```bash
$ tree
.
├── asymmetric
│   ├── import         // unseal an RSA Key on GCP
│   │   └── main.go
│   ├── seal           // Seal RSA key to a VMs ekPub
│   │   └── main.go
│   └── sign           // use TPM keyhandle to sign data
│       └── main.go
├── LICENSE
├── pcr_utils          // used to read and extend PCR values
│   ├── main.go
│   └── README.md
├── README.md
└── symmetric          // Seal/Unseal a symmetric key
    └── main.go
```


### Create Confidential Compute Instance

```bash
gcloud beta compute  instances create cc   --zone=us-central1-a \
 --machine-type=n2d-standard-2   --confidential-compute   --subnet=default \
 --network-tier=PREMIUM --maintenance-policy=TERMINATE  \
 --no-service-account --no-scopes --image=ubuntu-1804-bionic-v20200716  \
 --image-project=confidential-vm-images
```

[install golang](https://golang.org/doc/install)


### Sealed Symmetric Key

- On laptop, acquire Endorsement Public key

```bash
gcloud compute instances get-shielded-identity cc --format="value(encryptionKey.ekPub)" > /tmp/ek.pem
```

- On VM extend PCR value for PCR=23

```bash
gcloud compute ssh cc
sudo su -
git clone https://github.com/salrashid123/gcp_tpm_sealed_keys.git
```

- Print the default value:

```bash
go run pcr_utils/main.go --mode=read --pcr=23 -v 10 -alsologtostderr

    I1006 16:05:32.472993    2758 main.go:66] ======= Print PCR  ========
    I1006 16:05:32.474946    2758 main.go:71] PCR(23) 0000000000000000000000000000000000000000000000000000000000000000
```


- Increment the PCR so we have non-default value (we just do this step for demonstration)

```bash
go run pcr_utils/main.go --mode=extend --pcr=23 -v 10 -alsologtostderr
    I1006 16:06:55.159899    2812 main.go:74] ======= Extend PCR  ========
    I1006 16:06:55.161682    2812 main.go:79] Current PCR(23) 0000000000000000000000000000000000000000000000000000000000000000
    I1006 16:06:55.164941    2812 main.go:92] New PCR(23) f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4
```

- On laptop, seal key data to PCR=23 with value `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4`

```bash
$ go run symmetric/main.go  --mode=seal --secret "hello world" --ekPubFile=/tmp/ek.pem --pcrValues=23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b   --sealedDataFile=sealed.dat --logtostderr=1 -v 10
    I1006 12:52:27.056727  903568 main.go:65] PCR key: 23
    I1006 12:52:27.057173  903568 main.go:98] Sealed data to file.. sealed.dat
```

- Copy `sealed.dat` to VM

- on VM, unseal 

```bash
$ go run symmetric/main.go --mode=unseal --sealedDataFile=sealed.dat --logtostderr=1 -v 10
    I1006 16:54:56.647861    3714 main.go:145] Unsealed secret: hello world
```

### Sealed Asymmetric Key

- On laptop, generate RSA key
```bash
openssl genrsa -out /tmp/key.pem 2048
```

- On laptop, seal RSA key and create test signature

Note, we are using the new PCR value from the previous section `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`
```bash

$ go run asymmetric/seal/main.go   \
     --rsaKeyFile=/tmp/key.pem  \
     --sealedOutput=sealed.dat  \
     --ekPubFile=/tmp/ek.pem \
     --pcrValues=23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b \
      --v=10 -alsologtostderr

    I1006 13:18:43.204890  908867 main.go:65] PCR key: 23
    I1006 13:18:43.205066  908867 main.go:81] ======= Init createSigningKeyImportBlob ========
    I1006 13:18:43.205077  908867 main.go:83] ======= Loading ekPub ========
    I1006 13:18:43.205136  908867 main.go:99] ======= Loading Service Account RSA Key ========
    I1006 13:18:43.205236  908867 main.go:113] ======= Generating Test Signature ========
    I1006 13:18:43.207006  908867 main.go:126] Signature: H4pl1iLxjuKN7n1tHsu1V5Bh/xeL/HaqvS4K6hPChBaczXuw76SVK6usBYJAYuRhdPN7jUkj/UIbw16Leo42b2o2N9pphME103iJGx+4m4OSW1rMAlPu9D7PWWH77kVNRN2/9tWDMexpVDsMChgGoTXh3X4XZ+Igt1zmTDW9kKZAG3Lkhi7FVuJ4whsT1xSC1xmHsJrhH9aKCnmJxd6poUVN4LOLcCPt5zktwOMLdx9qjGgXXxjeGLUq50SgrzMgxELFE/tgRhscycYCMZr1MvHUq1zcCF+xu8wHTMczqyDISg/k9A39an9BWG7nCUQ1tuuHEnEfgQ3GhPwchVFjDw==
    I1006 13:18:43.207019  908867 main.go:128] ======= CreateSigningKeyImportBlob for RSA Key: ========
    I1006 13:18:43.207171  908867 main.go:140] ======= Saving sealedkey ========
    I1006 13:18:43.207262  908867 main.go:150] Sealed data to file.. sealed.dat
```

- Copy sealed.dat to VM

- on VM import RSA Key

Specify the PCR value to use while creating test signature

```bash

$ go run asymmetric/import/main.go   --importSigningKeyFile=sealed.dat \
  --keyHandleOutputFile=key.dat   --bindPCRValue=23 \
  --flush=all   --v=2 -alsologtostderr

    I1006 17:20:29.310822    4131 main.go:51] ======= Init importSigningKey ========
    I1006 17:20:29.397259    4131 main.go:73] Handle 0x3000000 flushed
    I1006 17:20:29.400073    4131 main.go:79] ======= Print PCR  ========
    I1006 17:20:29.401936    4131 main.go:84] Using PCR: %!i(int=23) f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
    I1006 17:20:29.401973    4131 main.go:86] ======= Loading EndorsementKeyRSA ========
    I1006 17:20:29.407012    4131 main.go:93] ======= Loading sealedkey ========
    I1006 17:20:29.407212    4131 main.go:104] ======= Loading ImportSigningKey ========
    I1006 17:20:29.445478    4131 main.go:136] ======= Signing Data with Key Handle ========
    I1006 17:20:29.453321    4131 main.go:181] Test Signature: H4pl1iLxjuKN7n1tHsu1V5Bh/xeL/HaqvS4K6hPChBaczXuw76SVK6usBYJAYuRhdPN7jUkj/UIbw16Leo42b2o2N9pphME103iJGx+4m4OSW1rMAlPu9D7PWWH77kVNRN2/9tWDMexpVDsMChgGoTXh3X4XZ+Igt1zmTDW9kKZAG3Lkhi7FVuJ4whsT1xSC1xmHsJrhH9aKCnmJxd6poUVN4LOLcCPt5zktwOMLdx9qjGgXXxjeGLUq50SgrzMgxELFE/tgRhscycYCMZr1MvHUq1zcCF+xu8wHTMczqyDISg/k9A39an9BWG7nCUQ1tuuHEnEfgQ3GhPwchVFjDw==
```


### Alter PCR value

- On VM

```bash
$ go run pcr_utils/main.go --mode=extend --pcr=23 -v 10 -alsologtostderr
    I1006 17:24:04.232798    4260 main.go:73] ======= Extend PCR  ========
    I1006 17:24:04.234695    4260 main.go:78] Current PCR(23) f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
    I1006 17:24:04.238030    4260 main.go:91] New PCR(23) db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71
```

- Attempt to decrypt symmetric  `sealed.dat`

```bash
$ go run symmetric/main.go --mode=unseal --sealedDataFile=sealed.dat --logtostderr=1 -v 10
    I1006 17:25:15.127342    4319 main.go:145] Unsealed secret: 
    F1006 17:25:15.127396    4319 main.go:147] Unable to Import sealed data: unseal failed: session 1, error code 0x1d : a policy check failed
```

- Attempt to import asymmetric `sealded.dat`

```bash
$ go run asymmetric/import/main.go   --importSigningKeyFile=sealed.dat \
  --keyHandleOutputFile=key.dat   --bindPCRValue=23 \
  --flush=all   --v=2 -alsologtostderr
    I1006 17:26:23.885236    4380 main.go:51] ======= Init importSigningKey ========
    I1006 17:26:23.898508    4380 main.go:73] Handle 0x3000000 flushed
    I1006 17:26:23.901770    4380 main.go:79] ======= Print PCR  ========
    I1006 17:26:23.903833    4380 main.go:84] Using PCR: %!i(int=23) db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71
    I1006 17:26:23.903873    4380 main.go:86] ======= Loading EndorsementKeyRSA ========
    I1006 17:26:23.909236    4380 main.go:93] ======= Loading sealedkey ========
    I1006 17:26:23.909402    4380 main.go:104] ======= Loading ImportSigningKey ========
    I1006 17:26:23.948927    4380 main.go:136] ======= Signing Data with Key Handle ========
    F1006 17:26:23.953802    4380 main.go:168] google: Unable to Sign with TPM: session 1, error code 0x1d : a policy check failed
```

- Attempt to embedded RSA Keyhandle `key.dat` that we loaded earlier bound to the previous PCR value (`f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b` )

  This will fail since we updated the value of PCR23.

```bash
$ go run main.go   --keyFile=key.dat   --bindPCRValue=23     --v=2 -alsologtostderr
    I1006 17:48:30.389303    5038 main.go:34] ======= Init  ========
    I1006 17:48:30.401942    5038 main.go:61] 0 handles flushed
    I1006 17:48:30.408789    5038 main.go:75] ======= Signing Data with Key Handle ========
    F1006 17:48:30.413426    5038 main.go:107] google: Unable to Sign with TPM: session 1, error code 0x1d : a policy check failed
```

#### Appendix

- [Duplicate and Transfer](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
