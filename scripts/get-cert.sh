export RAUC_PKCS11_MODULE="/home/mgrand/trustnsign-pkcs11/trustnsign-pkcs11-x64.so"
export TNS_URL="https://tnsdemo.trustngo.tech/_/api"
export TNS_USERNAME="m.grand@trustngo.tech"

pkcs11-tool --module $RAUC_PKCS11_MODULE --login --type cert -a $1 -r -o $1.cert.der
openssl x509 -inform DER -outform PEM -in $1.cert.der -out $1.cert.pem
rm $1.cert.der
