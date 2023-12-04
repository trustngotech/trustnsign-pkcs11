export RAUC_PKCS11_MODULE="/home/mgrand/trustnsign-pkcs11/trustnsign-pkcs11-x64.so"
export TNS_URL="https://tnsdemo.trustngo.tech/_/api"
export TNS_USERNAME="m.grand@trustngo.tech"
export OPENSSL_CONF="$(realpath ../engine.conf)"

chmod 0644 $2
rauc extract-signature --keyring ./example-ca/ca.cert.pem $2 extracted-signature.cms
openssl cms -verify -noverify -out manifest.raucm -inform DER -in extracted-signature.cms
openssl cms -engine pkcs11 -keyform engine -sign -signer ./example-ca/$1.cert.pem \
-CAfile ./example-ca/ca.cert.pem -inkey "pkcs11:object=$1" \
-nodetach -noattr -in manifest.raucm -outform der -out new-signature.cms
rauc replace-signature --keyring ./example-ca/ca.cert.pem --signing-keyring ./example-ca/ca.cert.pem $2 new-signature.cms $3
chmod 0644 $3
rm *.cms *.raucm
