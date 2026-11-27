module github.com/helsingin/keyman/tests/openssl

go 1.26.0

require github.com/helsingin/keyman v0.0.0

require github.com/miekg/pkcs11 v1.1.2 // indirect

replace github.com/helsingin/keyman => ../..
