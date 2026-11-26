module github.com/helsingin/keyman/tests/pqc

go 1.26.0

require (
	github.com/helsingin/keyman v0.0.0
	github.com/helsingin/pqc v0.2.0
)

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/helsingin/keyman => ../..
