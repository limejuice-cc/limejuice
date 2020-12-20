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
	specs "github.com/limejuice-cc/api/go-api/crypto/v1alpha"
)

type localdCertificateProvider struct {
}

func (p *localdCertificateProvider) Initialize(options ...specs.CertificateProviderOption) error {
	return nil
}

func (p *localdCertificateProvider) ParseEncoded(certificate, privateKey []byte) (specs.Certificate, error) {
	return ParseEncodedCertificate(certificate, privateKey)
}

func (p *localdCertificateProvider) Generate(request *specs.CertificateRequest) (specs.Certificate, error) {
	return GenerateCertificate(request)
}

// NewLocalCertificateProvider creates a new local self-signed certificate provider
func NewLocalCertificateProvider() specs.CertificateProvider {
	return &localdCertificateProvider{}
}
