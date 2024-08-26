## Transferring RSA and Symmetric keys with GCP vTPMs

Sample applications that transfers keys to [TPM](https://en.wikipedia.org/wiki/Trusted_Platform_Module) [Platform Configuration Registers (PCR)](https://link.springer.com/chapter/10.1007/978-1-4302-6584-9_12) values using Google [Confidential Compute](https://cloud.google.com/confidential-computing) instances

This repo demonstrates how a remote user can acquire a GCP VM's unique [Endorsement Public key](https://cloud.google.com/security/shielded-cloud/retrieving-endorsement-key) and then use that to encrypt a key such that it can only get decrypted _on that vm_.

In addition, the key is sealed using a PCR policy that mandates the key can only be unsealed or used if specific PCR values are present on that VM 
and if the VM gets deleted, the key cannot be unsealed.

There are two types of keys that are sealed and transferred

* transfers arbitrary data to a TPM
  An arbitrary key which can be a simple AES key or in the example below, just "hello world".  Just note, the arbitrary data is encrypted such that it can only be decrypted by that TPM.  It does not import the arbitrary data _into_ the target TPM.  The capability to embed a key into a TPM is not yet implemented in `go-tpm-tools` but it is covered under `tpm-tools` [Duplicate and Transfer](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate)

* transfers RSA Private key to TPM
  An RSA private key that is transferred and **embedded into the TPM**.  Note: once an RSA key is imported, the TPM will only use it to sign data.
  The raw embedded key will not get exported outside of the TPM.   In this mode, the RSA key is unsealed _into_ the target TPM (eg, imported)

In the final step, we will alter/extend the PCR value we originally sealed data against.  This will prevent any further unsealing of the symmetric key as well as prevent import of the RSA key.  Furthermore, since we imported an RSA key with a different PCR value earlier, this will prevent using the TPM to sign  using that RSA key.


---

### Setup

```bash
$ tree
.
├── asymmetric
│   ├── import         // unseal an RSA Key on GCP
│   │   └── main.go
│   ├── persistent
│   │   └── main.go    // Seal and Unseal RSA key to VMs ekPUB but write the TPM's RSA key reference public/private key to files
│   ├── seal           // Seal RSA key to a VMs ekPub
│   │   └── main.go
│   └── sign           // use TPM keyhandle to sign data
│       └── main.go
├── LICENSE
├── cert_parser        // parse the EKCertificate and extract the custom OID values
│   ├── go.mod
│   ├── go.sum
│   └── main.go
├── pcr_utils          // used to read and extend PCR values
│   ├── main.go
│   └── README.md
├── README.md
└── symmetric          // Seal/Unseal a symmetric key
    └── main.go
```


### Create Confidential Compute Instance

```bash
gcloud compute  instances create cc   --zone=us-central1-a \
    --machine-type=n2d-standard-2  --min-cpu-platform="AMD Milan"  \
    --shielded-secure-boot --no-service-account --no-scopes  \
    --shielded-vtpm --confidential-compute-type=SEV
```

[install golang](https://golang.org/doc/install)

```bash
gcloud compute ssh cc
sudo su -
apt-get update
wget https://go.dev/dl/go1.20.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```


### Acquire

- On laptop, acquire Endorsement Certificate and Public key

```bash
# get public key
gcloud compute instances get-shielded-identity cc --format="value(encryptionKey.ekPub)" > /tmp/ek.pem
```

You can also get the EK using `tpm2_tools` directly from the VM:  see [Read EK keys](https://github.com/salrashid123/tpm2/tree/master/gcp_ek_ak#read-ek-keys-on-gce)

### Transfer Symmetric Key


- On `cc` VM we create, extend PCR value for `PCR=23`

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
go run symmetric/main.go  --mode=seal \
   --secret "hello world" \
   --ekPubFile=/tmp/ek.pem \
   --pcrValues=23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b   \
   --sealedDataFile=sealed.dat --logtostderr=1 -v 10
  
    I1006 12:52:27.056727  903568 main.go:65] PCR key: 23
    I1006 12:52:27.057173  903568 main.go:98] Sealed data to file.. sealed.dat
```

- Copy `sealed.dat` to VM (eg, `/tmp/sealed.dat`)

- on VM, unseal 

```bash
$ go run symmetric/main.go --mode=unseal --sealedDataFile=/tmp/sealed.dat --logtostderr=1 -v 10
    I1006 16:54:56.647861    3714 main.go:145] Unsealed secret: hello world
```

### Transfer Asymmetric Key

- On laptop, generate *RSA key*
```bash
openssl genrsa -out /tmp/key.pem 2048

openssl rsa -in /tmp/key.pem -out /tmp/key_rsa.pem -traditional
```

>> note the private key  needs to be in `ParsePKCS8PrivateKey` format (thats just because i'm lazy)


- On laptop, seal RSA key and create test signature

Note, we are using the new PCR value from the previous section `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`
```bash

$ go run asymmetric/seal/main.go   \
     --rsaKeyFile=/tmp/key_rsa.pem  \
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

$ go run asymmetric/import/main.go   --importSigningKeyFile=/tmp/sealed.dat \
  --persistentHandle=0x81008000 --flush=all --evict=true  --bindPCRValue=23 \
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

Note, the Test signature generated locally compared to what was on the TPM after unsealing is the same.


#### Transfer Asymmetric Key with persistent files

##### on laptop

The following program will seal and unseal an RSA key but critically, the imported RSA key on the tpm has the public/private key saved to files.

THis means the key can be reused after reboots easily.

```bash
gcloud compute instances get-shielded-identity instance-1 --format="value(encryptionKey.ekPub)" > /tmp/ek.pem

openssl genrsa -out /tmp/key.pem 2048
openssl rsa -in /tmp/key.pem -out /tmp/key_rsa.pem -traditional
```

##### Without PCR Policy


```bash
go run asymmetric/seal/main.go   \
     --rsaKeyFile=/tmp/key_rsa.pem  \
     --sealedOutput=sealsealed_no_pcred.dat  \
     --ekPubFile=/tmp/ek.pem \
      --v=10 -alsologtostderr

gcloud compute scp sealed_no_pcr.dat instance-1:/tmp/sealed_no_pcr.dat
```

##### on instance-1

```bash
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=import --pub pub.dat -priv priv.dat --importSigningKeyFile=sealed_no_pcr.dat   --flush=all
## by default the public/private references are saved to pub.dat and priv.dat

sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign --pub pub.dat -priv priv.dat  --flush=all

## reboot and read the pub.dat and priv.dat to sign data
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign --pub pub.dat -priv priv.dat  --flush=all
```


##### With PCR Policy

first alter the tpm's pcr value so we can test:

```bash
$ tpm2_pcrread sha256:23
$ tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
$ tpm2_pcrread sha256:23
    sha256:
      23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

on laptop

then seal to that pcr value

```bash 
go run asymmetric/seal/main.go   \
     --rsaKeyFile=/tmp/key_rsa.pem  \
     --sealedOutput=sealed_pcr.dat  --pcrValues=23=f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b   \
     --ekPubFile=/tmp/ek.pem \
      --v=10 -alsologtostderr

gcloud compute scp sealed_pcr instance-1:sealed_pcr.dat 
```

##### on instance-1

```bash
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=import --pub pub.dat -priv priv.dat --importSigningKeyFile=sealed_pcr.dat   --flush=all --bindPCRValues=23
## remember to set the pcr23 value forward
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign  --flush=all --pub pub.dat -priv priv.dat  --bindPCRValues=23
## reboot, remember to reset the pcr23 value forward
sudo /usr/local/go/bin/go run asymmetric/persistent/main.go --mode=sign  --flush=all --pub pub.dat -priv priv.dat  --bindPCRValues=23
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

- Attempt to import asymmetric `sealed.dat`

```bash
$ go run asymmetric/import/main.go   --importSigningKeyFile=sealed.dat \
  --persistentHandle=0x81008000  --evict=true --bindPCRValue=23 \
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
$ go run main.go   --persistentHandle=0x81008000   --bindPCRValue=23     --v=2 -alsologtostderr
    I1006 17:48:30.389303    5038 main.go:34] ======= Init  ========
    I1006 17:48:30.401942    5038 main.go:61] 0 handles flushed
    I1006 17:48:30.408789    5038 main.go:75] ======= Signing Data with Key Handle ========
    F1006 17:48:30.413426    5038 main.go:107] google: Unable to Sign with TPM: session 1, error code 0x1d : a policy check failed
```

#### Transfer RSA key with password policy from A->B

If you want to see what the sealed rsa transfer looks like using `tpm2_tools` and a password policy, then using sample from [tpm2_duplicate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_duplicate.1.md)



- TPM-B

```bash
$ tpm2_createprimary -c primary.ctx
$ tpm2_readpublic -c primary.ctx -o primary.pub

$ tpm2_print -t TPM2B_PUBLIC  primary.pub

## read as PEM
$ tpm2_readpublic -f PEM -c primary.ctx  -o primary.pem
```

copy primary.pub to TPM-A

- TPM-A

```bash
# $ openssl genrsa -out rsa.pem

$ cat rsa.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwlmH3di2JpoBUtE6JKXthqPnS2tZXqFS302RuQavVFwZ7l7z
MbgAEvqzrF+JIhGr4LEVJwfNBbzOCNu+fT55Vq5/Pt3hCibb7/B2N4I4trfjdt2t
7+Kd8h4plMrszfY/gvK7MQBINe0spSAPWdnWkGXFY4emRbwo3NmjpLaSv0489LTD
gOA9uaPEk2dudrGyACWmbGMKm/2mxGVCuFIvtqW/Az/tpJ8mWVZZX4kmOlIIKZSd
ctF3wvyv1fTVwcmxfqGeFkN5WcSvUipZguRVNgLPBuYIMhC8+H+C1bw8FV+9TLs6
sHMSHp9GfwDQnkdnx4kInxhkD3/AT3B1gUZiKwIDAQABAoIBAQCMzH4A+7pi1tm0
nP2phUhCbcXoPro9M1StkC3NRQmKbTsgFUvMrkfneBbo/0GDHBhQLRps71raGEGP
61ris3sGkF6BNg+N4j8eYi/S4RWjUi+JcupLSvswaCepsyXBxO+YN6/jvReTceMR
MdvNNWMbs49AHwsXpExaS5Yhg19nFcxJd6MOfmFvJ9UimPh7XgSCtmrdQ0XKPoxG
7vWaNERN7xqgDyYG0oR2i+/4sDZ5KolehXNjmdDD/8qwa4PVEgVBn9QaypHNC1nD
njG39hIPvdN1Ix8kn7jtzuB0qePnQLC+87R4KAOXFNG3FGgUmDFVAIy7CSLcAJNG
G8yQy/GhAoGBAO/aXjBK6QnE19eDbm/mKzZB2+IVrdVe7cuORrqBlRrTf8NbqxtT
aIBd3kBfuGGLwuJLWLsyy1wc/rx0SZ/MOOWxk+/QQKhvp4dxn2imCBoNvozU6/Xg
I5Iawos6rwM8VGAcaaRa/atlGUpmSp5cVBl//HKAO5PyKS/PIxPjfaZxAoGBAM9u
9VoEx1yEK4cJDIX1KWIBCMq9lXBYv09WsLERKdfo4hMwbuv2CMMadvqPEh3h+dKr
4r7/cyrIyx4ydkRLBD1JC0yMUTMftqm5WBrImUvjpSNt8oV90R8VBDrfHzpRrFfj
9lEm0mKdl2Kn1R+Gu50aHNSwna+GhSjOgsHPK7hbAoGBALKaN6LcVTV6B4OqkfTv
PuQzHGn43K3S912pP0+oKICGV1AAlaROcrWLsHDdFi5E5USe+J7EzxtzV9i6+wvs
Bb48gj2EJHGIWwaHfD1vzP6hl2/FKUO4uKQWGyGT/Dh7lxTOc3f4bYZQTQnSq+PK
OrGWVURp6nNbUoIQSz2HG8xxAoGBAMAV7/28DyENA4G4T3B85iVq78lOZePzSrUd
geF2E1lsvm0mnJDE9Lg2+ZZshkpFyCHeKcrUosErz2vXLs1u6i4WRfBMv6Sn6W6h
w4SJ3er4kyOL3Njg+ZXe0Fvz4ecPWpjI8H+Vg5zuchFZeXIIQhPo6mnKYzr3RrfT
BCKUxdehAoGAA2lkBrhF/kw9i4bQ+ohOcIaU6cqF9PSlYKT/2LbP19C7O9Sld9rH
mdvDiyyIs7fXWnCuxPwl8PSjDCXbUrij2lQmgCndPWT8w2U22Y/E9xpGOwIQBd+P
YQJn9mZMKihGI5E381Oicx4jCBzpnGrVJ13j5rgyPmom6X55U6rwH3E=
-----END RSA PRIVATE KEY-----

$ echo "meet me at.." >file.txt
$ openssl dgst -sha256 -sign rsa.pem  file.txt | base64
    hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
    lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
    Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
    oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
    AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==


$ tpm2_startauthsession --policy-session -S session.dat
$ tpm2_policypassword -S session.dat -L policy.dat
$ tpm2_flushcontext session.dat
$ tpm2_duplicate -U primary.pub -G rsa -k rsa.pem -u rsa.pub -r rsa.dpriv -s rsa.seed -L policy.dat  -p testpassword
```

copy `rsa.pub`, `rsa.dpriv` and `rsa.seed` to `TPM-A`

- TPM-B

```bash
$ tpm2_import -C primary.ctx -G rsa -i rsa.dpriv -s rsa.seed -u rsa.pub -r rsa.priv
$ tpm2_load -C primary.ctx -c rsa.ctx -u rsa.pub -r rsa.priv

$ echo "meet me at.." >file.txt
$ tpm2_sign -c rsa.ctx -g sha256  -f plain -p testpassword -o sig.rss  file.txt

$ cat sig.rss | base64
    hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
    lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
    Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
    oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
    AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==
```


(or after reboot, reload the chain)
```bash
$ tpm2_createprimary -c primary.ctx
$ tpm2_load -C primary.ctx -c rsa.ctx -u rsa.pub -r rsa.priv
$ tpm2_sign -c rsa.ctx -g sha256  -f plain -p testpassword -o sig.rss  file.txt
```

for other policy support within go-tpm-tools,  see [go-tpm-tools/issues/350](https://github.com/google/go-tpm-tools/issues/350)

#### Duplicate and transfer using endorsement key

- TPM-B

```bash
tpm2_createek -c primary.ctx -G rsa -u ek.pub -Q
tpm2_readpublic -c primary.ctx -o primary.pub
tpm2_readpublic -c primary.ctx -o ek.pem -f PEM -Q


$ more ek.pem
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5oXTo399gxaBu7eaigVX
  eHkoT0rQqyBvL0ifC7gTMGqoXZprYH728klHbCZv90Sfmqznw0j8RjN6Lj5W6Fp1
  Oq6TrOeQX4En8s9bVvPFgUIjFE5xnZWgWdwsmftnYscvD9QP7LIHUs7E43fjUn3s
  ARui25kfbu+NYq9QqElQZjxwMtjWd+J3mG7Via8UZKOW1ny68SNeLkhlO44IBvWf
  kpDNRIjbKeDiM9x+HwFZGQ1eZMRfvLFLHmVwnA1iEZ3O5UmgapzxSpsk0tbxp3f9
  JFEF95/JQ2qM/OoOHnMA8m+Yv30Px+7jDWB8ZK58nsU8Hd/l5N/WrILH7Sp0gAXW
  MwIDAQAB
  -----END PUBLIC KEY-----

## copy primary.pub to tpm-a
```

- TPM-A

```bash
$ cat rsa.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwlmH3di2JpoBUtE6JKXthqPnS2tZXqFS302RuQavVFwZ7l7z
MbgAEvqzrF+JIhGr4LEVJwfNBbzOCNu+fT55Vq5/Pt3hCibb7/B2N4I4trfjdt2t
7+Kd8h4plMrszfY/gvK7MQBINe0spSAPWdnWkGXFY4emRbwo3NmjpLaSv0489LTD
gOA9uaPEk2dudrGyACWmbGMKm/2mxGVCuFIvtqW/Az/tpJ8mWVZZX4kmOlIIKZSd
ctF3wvyv1fTVwcmxfqGeFkN5WcSvUipZguRVNgLPBuYIMhC8+H+C1bw8FV+9TLs6
sHMSHp9GfwDQnkdnx4kInxhkD3/AT3B1gUZiKwIDAQABAoIBAQCMzH4A+7pi1tm0
nP2phUhCbcXoPro9M1StkC3NRQmKbTsgFUvMrkfneBbo/0GDHBhQLRps71raGEGP
61ris3sGkF6BNg+N4j8eYi/S4RWjUi+JcupLSvswaCepsyXBxO+YN6/jvReTceMR
MdvNNWMbs49AHwsXpExaS5Yhg19nFcxJd6MOfmFvJ9UimPh7XgSCtmrdQ0XKPoxG
7vWaNERN7xqgDyYG0oR2i+/4sDZ5KolehXNjmdDD/8qwa4PVEgVBn9QaypHNC1nD
njG39hIPvdN1Ix8kn7jtzuB0qePnQLC+87R4KAOXFNG3FGgUmDFVAIy7CSLcAJNG
G8yQy/GhAoGBAO/aXjBK6QnE19eDbm/mKzZB2+IVrdVe7cuORrqBlRrTf8NbqxtT
aIBd3kBfuGGLwuJLWLsyy1wc/rx0SZ/MOOWxk+/QQKhvp4dxn2imCBoNvozU6/Xg
I5Iawos6rwM8VGAcaaRa/atlGUpmSp5cVBl//HKAO5PyKS/PIxPjfaZxAoGBAM9u
9VoEx1yEK4cJDIX1KWIBCMq9lXBYv09WsLERKdfo4hMwbuv2CMMadvqPEh3h+dKr
4r7/cyrIyx4ydkRLBD1JC0yMUTMftqm5WBrImUvjpSNt8oV90R8VBDrfHzpRrFfj
9lEm0mKdl2Kn1R+Gu50aHNSwna+GhSjOgsHPK7hbAoGBALKaN6LcVTV6B4OqkfTv
PuQzHGn43K3S912pP0+oKICGV1AAlaROcrWLsHDdFi5E5USe+J7EzxtzV9i6+wvs
Bb48gj2EJHGIWwaHfD1vzP6hl2/FKUO4uKQWGyGT/Dh7lxTOc3f4bYZQTQnSq+PK
OrGWVURp6nNbUoIQSz2HG8xxAoGBAMAV7/28DyENA4G4T3B85iVq78lOZePzSrUd
geF2E1lsvm0mnJDE9Lg2+ZZshkpFyCHeKcrUosErz2vXLs1u6i4WRfBMv6Sn6W6h
w4SJ3er4kyOL3Njg+ZXe0Fvz4ecPWpjI8H+Vg5zuchFZeXIIQhPo6mnKYzr3RrfT
BCKUxdehAoGAA2lkBrhF/kw9i4bQ+ohOcIaU6cqF9PSlYKT/2LbP19C7O9Sld9rH
mdvDiyyIs7fXWnCuxPwl8PSjDCXbUrij2lQmgCndPWT8w2U22Y/E9xpGOwIQBd+P
YQJn9mZMKihGI5E381Oicx4jCBzpnGrVJ13j5rgyPmom6X55U6rwH3E=
-----END RSA PRIVATE KEY-----

echo "meet me at.." >file.txt
openssl dgst -sha256 -sign rsa.pem  file.txt | base64
  hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
  lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
  Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
  oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
  AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==



tpm2_startauthsession --policy-session -S session.dat
tpm2_policypassword -S session.dat -L policy.dat
tpm2_flushcontext session.dat
tpm2_duplicate -U ek.pub -G rsa -k rsa.pem -u rsa.pub -r rsa.dpriv -s rsa.seed -L policy.dat  -p testpassword

## copy rsa.pub, rsa.dpriv, rsa.seed to tpm-b
```

- TPM-B

```bash

## ek uses  policysecret session https://github.com/tpm2-software/tpm2-tss/issues/2367#issuecomment-1147916014
tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement
tpm2 createek --ek-context ek.ctx

tpm2_import --parent-context ek.ctx  -G rsa -i rsa.dpriv -s rsa.seed -u rsa.pub -r rsa.priv --parent-auth session:session.ctx


tpm2 flushcontext -t
tpm2 startauthsession --session session.ctx --policy-session
tpm2 policysecret --session session.ctx --object-context endorsement

tpm2_load -C ek.ctx -c rsa.ctx -u rsa.pub -r rsa.priv --auth session:session.ctx

echo "meet me at.." >file.txt
tpm2_sign -c rsa.ctx -g sha256  -f plain -p testpassword -o sig.rss  file.txt
  hBZMi+lPLdx7/k+V2auCxcMrAE+mjXzsNvDFYHV9Zqil3990vauF8vfaO9GZeWdBWV45YdmJvsh0
  lrPog5b68hvmvx0A1row7ZrjWCuy6o2lXc04NIzrPSXC+nQb7ptnf5PET8VF6GamcDi5+1Zp5IOH
  Wxz82T+AkIFGY16Hz04qmkIUrBnzwuhbpaYY4XzBUPQTvhH2IWmO7y70rDBYoSYLfQtBGWVbfgAf
  oNglCIJmR0ctq6+FFa1EmhXNIjfgvwjvDXmpDMJDqsNZKgEdljlP155cWoqKNEO/3ypVEP51u6EU
  AD7hypXO5Femy+/AZhD7VUu1gp0TWOOTvPqs+Q==
```



finally, since i was using a gce instance, i can use the api to get the EKPub KEY

```bash
$ gcloud compute instances get-shielded-identity instance-2 --format="value(encryptionKey.ekPub)"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5oXTo399gxaBu7eaigVX
eHkoT0rQqyBvL0ifC7gTMGqoXZprYH728klHbCZv90Sfmqznw0j8RjN6Lj5W6Fp1
Oq6TrOeQX4En8s9bVvPFgUIjFE5xnZWgWdwsmftnYscvD9QP7LIHUs7E43fjUn3s
ARui25kfbu+NYq9QqElQZjxwMtjWd+J3mG7Via8UZKOW1ny68SNeLkhlO44IBvWf
kpDNRIjbKeDiM9x+HwFZGQ1eZMRfvLFLHmVwnA1iEZ3O5UmgapzxSpsk0tbxp3f9
JFEF95/JQ2qM/OoOHnMA8m+Yv30Px+7jDWB8ZK58nsU8Hd/l5N/WrILH7Sp0gAXW
MwIDAQAB
-----END PUBLIC KEY-----
```


#### Appendix

- [Duplicate and Transfer](https://github.com/salrashid123/tpm2/tree/master/tpm2_duplicate)
- [Trusted Platform Module (TPM) recipes with tpm2_tools and go-tpm](https://github.com/salrashid123/tpm2)
