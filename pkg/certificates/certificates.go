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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	specs "github.com/limejuice-cc/api/go-api/crypto/v1alpha"
)

type certificateHosts struct {
	dnsNames       []string
	emailAddresses []string
	ipAddresses    []net.IP
	uris           []*url.URL
}

func (h *certificateHosts) DNSNames() []string {
	return h.dnsNames
}

func (h *certificateHosts) EmailAddresses() []string {
	return h.emailAddresses
}

func (h *certificateHosts) IPAddresses() []net.IP {
	return h.ipAddresses
}

func (h *certificateHosts) URIs() []*url.URL {
	return h.uris
}

func certificateHostsFromCertificate(cert *x509.Certificate) specs.CertificateHosts {
	return &certificateHosts{
		dnsNames:       cert.DNSNames,
		emailAddresses: cert.EmailAddresses,
		ipAddresses:    cert.IPAddresses,
		uris:           cert.URIs,
	}
}

func certificateHostsFromCertificateRequest(request *specs.CertificateRequest) specs.CertificateHosts {
	out := &certificateHosts{
		dnsNames:       []string{},
		emailAddresses: []string{},
		ipAddresses:    []net.IP{},
		uris:           []*url.URL{},
	}
	for _, host := range request.Hosts {
		if ip := net.ParseIP(host); ip != nil {
			out.ipAddresses = append(out.ipAddresses, ip)
			continue
		}

		if email, err := mail.ParseAddress(host); err == nil && email != nil {
			out.emailAddresses = append(out.emailAddresses, email.Address)
			continue
		}

		if uri, err := url.ParseRequestURI(host); err == nil && uri != nil {
			out.uris = append(out.uris, uri)
			continue
		}

		out.dnsNames = append(out.dnsNames, host)
	}

	return out
}

type distinguishedName struct {
	commonName          string
	countries           []string
	provinces           []string
	localities          []string
	organizations       []string
	organizationalUnits []string
	serialNumber        *big.Int
}

func (n *distinguishedName) CommonName() string {
	return n.commonName
}

func (n *distinguishedName) Countries() []string {
	return n.countries
}

func (n *distinguishedName) Provinces() []string {
	return n.provinces
}

func (n *distinguishedName) States() []string {
	return n.provinces
}

func (n *distinguishedName) Localities() []string {
	return n.localities
}

func (n *distinguishedName) Organizations() []string {
	return n.organizations
}

func (n *distinguishedName) OrganizationalUnits() []string {
	return n.organizationalUnits
}

func (n *distinguishedName) SerialNumber() *big.Int {
	return n.serialNumber
}

func (n *distinguishedName) setSerialNumber(serialNumber string) {
	serialNumber = strings.TrimSpace(serialNumber)
	if len(serialNumber) > 0 {
		n.serialNumber = new(big.Int)
		if _, ok := n.serialNumber.SetString(serialNumber, 10); !ok {
			n.serialNumber = nil
		}
	}
}

func (n *distinguishedName) getSubject() *pkix.Name {
	out := &pkix.Name{
		CommonName:         n.commonName,
		Country:            n.countries,
		Province:           n.provinces,
		Locality:           n.localities,
		Organization:       n.organizations,
		OrganizationalUnit: n.organizationalUnits,
	}
	if n.serialNumber != nil {
		out.SerialNumber = n.serialNumber.String()
	}
	return out
}

func distinguishedNameFromSubject(subject *pkix.Name) specs.DistinguishedName {
	out := &distinguishedName{}
	out.commonName = subject.CommonName
	out.setSerialNumber(subject.SerialNumber)
	out.countries = subject.Country
	out.provinces = subject.Province
	out.localities = subject.Locality
	out.organizations = subject.Organization
	out.organizationalUnits = subject.OrganizationalUnit
	return out
}

func distinguishedNameFromcertificateRequest(request *specs.CertificateRequest) specs.DistinguishedName {
	out := &distinguishedName{}
	out.commonName = strings.TrimSpace(request.CommonName)
	for _, name := range request.Names {
		c := strings.TrimSpace(name.C)
		if len(c) > 0 {
			out.countries = append(out.countries, c)
		}

		st := strings.TrimSpace(name.ST)
		if len(st) > 0 {
			out.provinces = append(out.provinces, st)
		}

		l := strings.TrimSpace(name.L)
		if len(l) > 0 {
			out.localities = append(out.localities, l)
		}

		o := strings.TrimSpace(name.O)
		if len(o) > 0 {
			out.organizations = append(out.organizations, o)
		}

		ou := strings.TrimSpace(name.OU)
		if len(ou) > 0 {
			out.organizationalUnits = append(out.organizationalUnits, ou)
		}

		serialNumber := strings.TrimSpace(name.SerialNumber)
		if out.serialNumber == nil && len(name.SerialNumber) > 0 {
			out.setSerialNumber(serialNumber)
		}
	}
	return out
}

type baseCertificate struct {
	ca           bool
	subject      specs.DistinguishedName
	hosts        specs.CertificateHosts
	expires      time.Time
	usage        specs.CertificateKeyUsages
	serialNumber *big.Int

	encoded []byte

	certificate *x509.Certificate
	privateKey  specs.Key
}

func (c *baseCertificate) Encoded() []byte {
	return c.encoded
}

func (c *baseCertificate) Certificate() *x509.Certificate {
	return c.certificate
}

func (c *baseCertificate) PrivateKey() specs.Key {
	return c.privateKey
}

func (c *baseCertificate) CA() bool {
	return c.ca
}

func (c *baseCertificate) Subject() specs.DistinguishedName {
	return c.subject
}

func (c *baseCertificate) Hosts() specs.CertificateHosts {
	return c.hosts
}

func (c *baseCertificate) Expires() time.Time {
	return c.expires
}

func (c *baseCertificate) Usage() specs.CertificateKeyUsages {
	return c.usage
}

func (c *baseCertificate) SerialNumber() *big.Int {
	return c.serialNumber
}

func (c *baseCertificate) SelfSign() (specs.Certificate, error) {
	cert, err := x509.CreateCertificate(rand.Reader, c.certificate, c.certificate, c.privateKey.PublicKey(), c.privateKey.PrivateKey())
	if err != nil {
		return nil, err
	}

	return ParseEncodedCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), c.privateKey.Encoded())
}

func (c *baseCertificate) Sign(parentCertificate specs.Certificate) (specs.Certificate, error) {
	cert, err := x509.CreateCertificate(rand.Reader, c.certificate, parentCertificate.Certificate(), c.privateKey.PublicKey(), parentCertificate.PrivateKey().PrivateKey())
	if err != nil {
		return nil, err
	}
	return ParseEncodedCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), c.privateKey.Encoded())
}

// ParseEncodedCertificate parses a certificate and a private key for pem encoded bytes
func ParseEncodedCertificate(cert, key []byte) (specs.Certificate, error) {
	p, _ := pem.Decode(cert)
	parsed, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return nil, err
	}

	out := &baseCertificate{}
	out.encoded = cert
	out.certificate = parsed

	if privateKey, err := parsePrivateKey(key); err == nil {
		out.privateKey = privateKey
	} else {
		return nil, err
	}

	out.ca = parsed.IsCA
	out.subject = distinguishedNameFromSubject(&parsed.Subject)
	out.hosts = certificateHostsFromCertificate(parsed)
	out.expires = out.certificate.NotAfter
	out.usage = certificateKeyUsagesFromCertificate(parsed)
	out.serialNumber = parsed.SerialNumber

	return out, nil
}

// GenerateCertificate generates a certificate from a request
func GenerateCertificate(request *specs.CertificateRequest) (specs.Certificate, error) {
	cert := &baseCertificate{
		encoded: []byte{},
		ca:      request.IsCA,
		subject: distinguishedNameFromcertificateRequest(request),
		hosts:   certificateHostsFromCertificateRequest(request),
		expires: time.Now().Add(request.Expires).UTC(),
		usage:   parseCertificateKeyUsages(request.Usage),
	}

	serialNumber := strings.TrimSpace(request.SerialNumber)
	if len(serialNumber) > 0 {
		cert.serialNumber = new(big.Int)
		if _, ok := cert.serialNumber.SetString(serialNumber, 10); !ok {
			cert.serialNumber = nil
		}
	}

	if cert.serialNumber == nil {
		if serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64)); err != nil {
			cert.serialNumber = serialNumber
		} else {
			return nil, err
		}
	}

	privateKey, err := GenerateKey(&request.Key)
	if err != nil {
		return nil, err
	}
	cert.privateKey = privateKey

	cert.certificate = &x509.Certificate{
		Subject:               *cert.subject.(*distinguishedName).getSubject(),
		PublicKey:             privateKey.PublicKey(),
		PublicKeyAlgorithm:    privateKey.PublicKeyAlgorithm(),
		SignatureAlgorithm:    privateKey.SignatureAlgorithm(),
		IPAddresses:           cert.hosts.IPAddresses(),
		EmailAddresses:        cert.hosts.EmailAddresses(),
		URIs:                  cert.Hosts().URIs(),
		DNSNames:              cert.hosts.DNSNames(),
		SerialNumber:          cert.certificate.SerialNumber,
		NotBefore:             time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:              cert.expires,
		KeyUsage:              cert.usage.Standard(),
		ExtKeyUsage:           cert.Usage().Extended(),
		BasicConstraintsValid: true,
		IsCA:                  cert.ca,
	}

	return cert, nil
}

