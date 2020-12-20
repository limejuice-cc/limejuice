// Copyright 2020 Limejuice-cc Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certificates

import (
	"crypto/x509"
	specs "github.com/limejuice-cc/api/go-api/crypto/v1alpha"
)

type certificateKeyUsages struct {
	standardUsage x509.KeyUsage
	extendedUsage []x509.ExtKeyUsage
}

func (u *certificateKeyUsages) Standard() x509.KeyUsage {
	return u.standardUsage
}

func (u *certificateKeyUsages) Extended() []x509.ExtKeyUsage {
	return u.extendedUsage
}

func parseCertificateKeyUsages(usages []string) specs.CertificateKeyUsages {
	out := &certificateKeyUsages{
		extendedUsage: []x509.ExtKeyUsage{},
	}

	for _, usage := range usages {
		switch usage {
		case "signing":
			out.standardUsage |= x509.KeyUsageDigitalSignature
		case "digital signature":
			out.standardUsage |= x509.KeyUsageDigitalSignature
		case "content commitment":
			out.standardUsage |= x509.KeyUsageContentCommitment
		case "key encipherment":
			out.standardUsage |= x509.KeyUsageKeyEncipherment
		case "key agreement":
			out.standardUsage |= x509.KeyUsageKeyAgreement
		case "data encipherment":
			out.standardUsage |= x509.KeyUsageDataEncipherment
		case "cert sign":
			out.standardUsage |= x509.KeyUsageCertSign
		case "crl sign":
			out.standardUsage |= x509.KeyUsageCRLSign
		case "encipher only":
			out.standardUsage |= x509.KeyUsageEncipherOnly
		case "decipher only":
			out.standardUsage |= x509.KeyUsageDecipherOnly
		case "any":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageAny)
		case "server auth":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageServerAuth)
		case "client auth":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageClientAuth)
		case "code signing":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageCodeSigning)
		case "email protection":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageEmailProtection)
		case "s/mime":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageEmailProtection)
		case "ipsec end system":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageIPSECEndSystem)
		case "ipsec tunnel":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageIPSECTunnel)
		case "ipsec user":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageIPSECUser)
		case "timestamping":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageTimeStamping)
		case "ocsp signing":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageOCSPSigning)
		case "microsoft sgc":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		case "netscape sgc":
			out.extendedUsage = append(out.extendedUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)

		}
	}

	return out
}

func certificateKeyUsagesFromCertificate(cert *x509.Certificate) specs.CertificateKeyUsages {
	return &certificateKeyUsages{
		standardUsage: cert.KeyUsage,
		extendedUsage: cert.ExtKeyUsage,
	}
}

// DefaultCAUsage gets the default key usages for a certificate authority
func DefaultCAUsage() specs.CertificateKeyUsages {
	return parseCertificateKeyUsages([]string{"cert sign", "crl sign"})
}
