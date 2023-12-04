export RAUC_PKCS11_MODULE="/home/mgrand/trustnsign-pkcs11/trustnsign-pkcs11-x64.so"
export TNS_URL="https://tnsdemo.trustngo.tech/_/api"
export TNS_USERNAME="m.grand@trustngo.tech"

rauc bundle --cert="pkcs11:object=$1" --key="pkcs11:object=$1" --keyring=$2 $3 $4
