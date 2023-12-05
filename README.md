# PKCS11 interface for TrustnSign server

## Prerequisites

This PKCS11 interface has only been tested on Ubuntu 22.04. To install the required dependencies, enter the following command:

```bash
sudo apt install libjson-c-dev libcurl4-openssl-dev opensc gcc make opensc-pkcs11
```

## Installation

First clone the git repository:

```bash
git clone https://github.com/trustngotech/trustnsign-pkcs11.git
```

Then, build the PKCS11 library:

```bash
cd trustnsign-pkcs11
make
```

You will have to define the TNS_URL and TNS_USERNAME environment variables to allow the library to connect to the server backend.

```bash
export TNS_URL="https://tns.trustngo.tech/_/api"
export TNS_USERNAME="<user email>"
```

## Usage

### Using PKCS11 tool

First be sure to have an enabled account on the TrustnSign server and that the `TNS_URL` and `TNS_USERNAME` environment variables are correctly set.

**Listing keys**

To list the available keys linked to your account, enter the following command and when the tool asks for your PIN enter your account password.

```bash
pkcs11-tool -v --module /path/to/lib/trustnsign-pkcs11-x64.so --login -O
```

You can also directly provide your credential on the command line:

```bash
pkcs11-tool -v --module /path/to/trustnsign-pkcs11-x64.so --login -pin <password> -O 
```

**Signing**

To sign using an ECDSA private key, use the following commands:

```bash
openssl dgst -binary -sha256 <input file> > <hash file>
pkcs11-tool -v --module /path/to/trustnsign-pkcs11-x64.so --login -m ECDSA --id <id of an ECDSA private key> -s -i <hash file> -o <signature file>
```

If you are willing to use RSA instead:

```bash
openssl dgst -binary -sha256 <input file> > <hash file>
pkcs11-tool -v --module /path/to/trustnsign-pkcs11-x64.so --login --hash-algorithm sha256 -m RSA-PKCS-PSS --id <id of an RSA private key> -s -i <hash file> -o <signature file>
```

**Diplaying certificate content**

To display the content of a certificate, use the following command:

```bash
pkcs11-tool -v --module /path/to/trustnsign-pkcs11-x64.so --login --type cert -r -d <id of a certificate> | openssl x509 -text -noout
```

### Using OpenSSL

You cannot list keys using OpenSSL however youc can easily sign and verify a signature using this tool.

**Signing**

First, you will have to prepare an OpenSSL configuration file. Just use the file provided with this repository and edit it to pint to the actual location of the dynamic library.

To sign using an ECDSA or RSA private key, use the following commands:

```bash
openssl dgst -binary -sha256 <input_file> > <hash_file>
OPENSSL_CONF=/path/to/engine.conf openssl pkeyutl -sign -engine pkcs11 -keyform engine -inkey "pkcs11:object=<key_label>" -in <hash_file> -out <signature_file>
```

To verify the signature, use the following command :

```bash
OPENSSL_CONF=/path/to/engine.conf openssl pkeyutl -verify -engine pkcs11 -keyform engine -pubin -inkey "pkcs11:object=<key_label>" -in <hash_file> -sigfile <signature_file>
```

You can directly provide your password by using the following PKCS11 URI: `"pkcs11:object=<key_label>;pin-value=<your_password>"`.

More information on PKCS11 URI are available in [RFC7512](https://datatracker.ietf.org/doc/html/rfc7512).

### Signing a RAUC bundle

**Prerquisites**

Set an environment variable storing the path of the TrustnSign PKCS11 interface:
```bash
export RAUC_PKCS11_MODULE="/path/to/trustnsign-pkcs11-x64.so"
```

**Self-signed certificate**

First you need to generate a new private key and a self-signed certificate on the website side. Then, use the following command to download the certificate from the server:

```bash
pkcs11-tool --module /path/to/trustnsign-pkcs11-x64.so --login --type cert \
--id <cert_id> -r -o self-signed-certificate.der
openssl x509 -inform DER -outform PEM -in self-signed-certificate.der -out self-signed-certificate.pem
```

Finally, use the following command to sign your bundle using the TrustnSign:

```bash
rauc bundle --cert="pkcs11:object=<key_label>" --key="pkcs11:object=<key_label>" --keyring=cert.pem </path/to/files> </path/to/bundle>
```

**Simple CA**

TBD
