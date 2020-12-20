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

package main

import (
	specs "github.com/limejuice-cc/api/go-api/crypto/v1alpha"
	plg "github.com/limejuice-cc/api/go-api/plugins/v1alpha"
	"github.com/limejuice-cc/limejuice/pkg/certificates"
	"github.com/limejuice-cc/limejuice/pkg/mods"
)

var (
	// BuildVersion is the version set by go build
	BuildVersion string = "v0.0.0-debug"
	// BuildDate is the date of the build set by build go
	BuildDate string = "NA"
)

const (
	execName    string             = "local-certificate-generator"
	name        string             = "Local Certificate Provider"
	description string             = "Provides self-signed certificates from a local and ethereal certificate authority"
	pluginType  plg.LimePluginType = plg.CertificateGenerator
)

type provider struct {
	meta plg.LimePlugin
}

func (p *provider) Initialize(options ...specs.CertificateProviderOption) error {
	return nil
}

func (p *provider) ParseEncoded(certificate, privateKey []byte) (specs.Certificate, error) {
	return certificates.ParseEncodedCertificate(certificate, privateKey)
}

func (p *provider) Generate(request *specs.CertificateRequest) (specs.Certificate, error) {
	return certificates.GenerateCertificate(request)
}

// Provider is the exported plugin symbol
var Provider provider

func main() {
	Provider.meta = mods.NewLimePlugin(
		name,
		description,
		BuildVersion,
		BuildDate,
		pluginType,
		map[string]interface{}{
			"Initialize":   Provider.Initialize,
			"ParseEncoded": Provider.ParseEncoded,
			"Generate":     Provider.Generate,
		})
	mods.Run(Provider.meta, execName)
}
