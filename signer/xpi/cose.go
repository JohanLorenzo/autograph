package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"go.mozilla.org/cose"
)

// stringToCOSEAlg returns the cose.Algorithm for a string or nil if
// the algorithm isn't implemented
func stringToCOSEAlg(s string) (v *cose.Algorithm) {
	switch strings.ToUpper(s) {
	case cose.PS256.Name:
		v = cose.PS256
	case cose.ES256.Name:
		v = cose.ES256
	case cose.ES384.Name:
		v = cose.ES384
	case cose.ES512.Name:
		v = cose.ES512
	default:
		v = nil
	}
	return v
}

// generateIssuerEEKeyPair returns a public and private key pair for
// the provided COSEAlgorithm
func (s *PKCS7Signer) generateCOSEKeyPair(coseAlg *cose.Algorithm) (eeKey crypto.PrivateKey, eePublicKey crypto.PublicKey, err error) {
	var signer *cose.Signer

	if coseAlg == nil {
		err = fmt.Errorf("Cannot generate private key for nil cose Algorithm")
		return
	} else if coseAlg == cose.PS256 {
		const size = 2048
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate rsa private key of size %d", size)
			return
		}
		eePublicKey = eeKey.(*rsa.PrivateKey).Public()
	} else {
		signer, err = cose.NewSigner(coseAlg, nil)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate private key")
			return
		}
		eeKey = signer.PrivateKey
		eePublicKey = eeKey.(*ecdsa.PrivateKey).Public()
	}
	return
}


// isSupportedCOSEAlgValue returns whether the COSE alg value is supported or not
func isSupportedCOSEAlgValue(algValue interface{}) bool {
	return algValue == cose.PS256.Value || algValue == cose.ES256.Value || algValue == cose.ES384.Value || algValue == cose.ES512.Value
}

// isValidCOSESignature checks whether a COSE signature is a valid for XPIs
func isValidCOSESignature(sig cose.Signature) (eeCert *x509.Certificate, resultErr error) {
	if len(sig.Headers.Unprotected) != 0 {
		resultErr = fmt.Errorf("XPI COSE Signature must have an empty Unprotected Header")
		return
	}

	if len(sig.Headers.Protected) != 2 {
		resultErr = fmt.Errorf("XPI COSE Signature must have exactly two Protected Headers")
		return
	}
	algValue, ok := sig.Headers.Protected[1] // 1 is the compressed key for "alg"
	if !ok {
		resultErr = fmt.Errorf("XPI COSE Signature must have alg in Protected Headers")
		return
	}
	if !isSupportedCOSEAlgValue(algValue) {
		resultErr = fmt.Errorf("XPI COSE Signature must have alg %+v is not supported", algValue)
		return
	}

	kidValue, ok := sig.Headers.Protected[4] // 4 is the compressed key for "kid"
	if !ok {
		resultErr = fmt.Errorf("XPI COSE Signature must have kid in Protected Headers")
		return
	}
	kidBytes, ok := kidValue.([]byte)
	if !ok {
		resultErr = fmt.Errorf("XPI COSE Signature kid value is not bytes")
		return
	}

	eeCert, err := x509.ParseCertificate(kidBytes) // eeCert
	if err != nil {
		resultErr = errors.Wrapf(err, "XPI COSE Signature kid must decode to a parseable X509 cert")
		return
	}
	return
}

// isValidCOSEMessage checks whether a COSE SignMessage is a valid for
// XPIs and returns parsed intermediate and end entity certs
func isValidCOSEMessage(msg cose.SignMessage) (intermediateCerts, eeCerts []*x509.Certificate, resultErr error) {
	if msg.Payload != nil {
		resultErr = fmt.Errorf("Expected SignMessage payload to be nil, but got %+v", msg.Payload)
		return
	}
	if len(msg.Headers.Unprotected) != 0 {
		resultErr = fmt.Errorf("Expected SignMessage Unprotected headers to be empty, but got %+v", msg.Headers.Unprotected)
		return
	}

	if len(msg.Headers.Protected) != 1 {
		resultErr = fmt.Errorf("Expected SignMessage Protected headers must contain one value, but got %d", len(msg.Headers.Protected))
		return
	}
	kidValue, ok := msg.Headers.Protected[4] // 4 is the compressed key for "kid"
	if !ok {
		resultErr = fmt.Errorf("Expected SignMessage must have kid in Protected Headers")
		return
	}
	// check that all kid values are bytes and decode into certs
	kidArray, ok := kidValue.([]interface{})
	if !ok {
		resultErr = fmt.Errorf("Expected SignMessage Protected Headers kid value to be an array got %+v with type %T", kidValue, kidValue)
		return
	}
	for i, cert := range kidArray {
		certBytes, ok := cert.([]byte)
		if !ok {
			resultErr = fmt.Errorf("Expected SignMessage Protected Headers kid value %d to be a byte slice got %+v with type %T", i, cert, cert)
			return
		}
		intermediateCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			resultErr = errors.Wrapf(err, "SignMessage Signature Protected Headers kid value %d does not decode to a parseable X509 cert", i)
			return
		}
		intermediateCerts = append(intermediateCerts, intermediateCert)
	}

	for i, sig := range msg.Signatures {
		eeCert, err := isValidCOSESignature(sig)
		if err != nil {
			resultErr = errors.Wrapf(err, "cose signature %d is invalid", i)
			return
		}
		eeCerts = append(eeCerts, eeCert)
	}

	return
}
