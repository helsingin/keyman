// Package pkcs11 implements HSM-backed key lifecycle operations using PKCS#11.
//
// All objects created by this package are tagged with an application label so
// tests and demos can share a token without scanning unrelated objects.
package pkcs11
