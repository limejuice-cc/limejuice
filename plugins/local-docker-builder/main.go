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
	"fmt"

	specs "github.com/limejuice-cc/api/go-api/builder/v1alpha"
	plg "github.com/limejuice-cc/api/go-api/plugins/v1alpha"
	"github.com/limejuice-cc/limejuice/pkg/builder"
	"github.com/limejuice-cc/limejuice/pkg/mods"
)

var (
	// BuildVersion is the version set by go build
	BuildVersion string = "v0.0.0-debug"
	// BuildDate is the date of the build set by build go
	BuildDate string = "NA"
)

const (
	execName    string             = "local-docker-builder"
	name        string             = "Local Docker Build Request Provider"
	description string             = "Provides a local docker build request environment"
	pluginType  plg.LimePluginType = plg.GenericFileGenerator
)

type provider struct {
	meta plg.LimePlugin
}

func (p *provider) Initialize(options ...specs.BuildRequestProviderOption) error {
	return nil
}

func (p *provider) Execute(buildContext specs.BuildContext, buildRequest specs.BuildRequest) (specs.BuildRequestOutput, error) {
	dock, ok := buildRequest.(*builder.DockerBuilder)
	if !ok {
		return nil, fmt.Errorf("expected DockerBuilder")
	}
	return dock.Run(buildContext)
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
			"Initialize": Provider.Initialize,
			"Execute":    Provider.Execute,
		})
	mods.Run(Provider.meta, execName)
}
