package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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
