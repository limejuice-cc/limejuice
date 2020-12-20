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

package mods

import (
	"fmt"
	"time"

	"github.com/alecthomas/kong"
	common "github.com/limejuice-cc/api/go-api/common/v1alpha"
	specs "github.com/limejuice-cc/api/go-api/plugins/v1alpha"
	"github.com/rs/zerolog"
)

// BaseLimePlugin is a LimePlugin base struct
type BaseLimePlugin struct {
	name        string
	description string
	version     *common.Version
	buildDate   time.Time
	pluginType  specs.LimePluginType
	exports     map[string]interface{}
}

// Name returns the name of the plugin
func (p *BaseLimePlugin) Name() string {
	return p.name
}

// Description returns the description of the plugin
func (p *BaseLimePlugin) Description() string {
	return p.description
}

// Version returns the version of the plugin
func (p *BaseLimePlugin) Version() *common.Version {
	return p.version
}

// BuildDate returns the date the plugin was built
func (p *BaseLimePlugin) BuildDate() time.Time {
	return p.buildDate
}

// Type returns the LimePluginType
func (p *BaseLimePlugin) Type() specs.LimePluginType {
	return p.pluginType
}

// Exports exposes the symbols exported by the plugin
func (p *BaseLimePlugin) Exports() map[string]interface{} {
	return p.exports
}

// NewLimePlugin returns a new LimePlugin
func NewLimePlugin(name,
	description,
	buildVersion,
	buildDate string,
	pluginType specs.LimePluginType,
	exports map[string]interface{}) specs.LimePlugin {
	out := &BaseLimePlugin{
		name:        name,
		description: description,
		pluginType:  pluginType,
		exports:     exports,
	}

	if version, err := common.ParseVersion(buildVersion); err == nil {
		out.version = version
	}

	if buildDate, err := time.Parse(time.RFC3339, buildDate); err == nil {
		out.buildDate = buildDate
	}

	return out
}

// Context represents the command context
type Context struct {
	plugin specs.LimePlugin
}

// Globals represents global flags
type Globals struct {
	LogLevel string `help:"The logging level (debug|info|warn|error)" enum:"debug,info,warn,error" default:"info" env:"LIME_PACKER_LOG_LEVEL"`
	Verbose  bool   `short:"v" help:"Shortcut for log-level debug." env:"LIME_PACKER_VERBOSE" xor:"verbosity"`
	Silent   bool   `short:"s" help:"Disables output." env:"LIME_PACKER_SILENT" xor:"verbosity"`
}

// VersionCommand runs a command to display the current version
type VersionCommand struct {
}

// Run runs the version command
func (v *VersionCommand) Run(ctx *Context) error {
	fmt.Printf("%s %s (%s)\n", ctx.plugin.Name(), ctx.plugin.Version().String(), ctx.plugin.BuildDate().Format(time.RFC3339))
	return nil
}

var cli struct {
	Globals
	Version VersionCommand `cmd help:"Displays the current version." default:"1"`
}

// Run runs a LimePlugin
func Run(p specs.LimePlugin, executableName string) {
	ctx := kong.Parse(&cli,
		kong.Name(executableName),
		kong.Description(p.Description()),
		kong.UsageOnError())

	if cli.Silent && !cli.Verbose {
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	} else {
		if !cli.Verbose {
			logLevel, err := zerolog.ParseLevel(cli.LogLevel)
			if err == nil {
				zerolog.SetGlobalLevel(logLevel)
			}
		} else {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
	}

	err := ctx.Run(&Context{plugin: p})
	ctx.FatalIfErrorf(err)
}
