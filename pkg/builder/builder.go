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

package builder

import (
	"io"
	"io/ioutil"
	"os"

	specs "github.com/limejuice-cc/api/go-api/builder/v1alpha"
	common "github.com/limejuice-cc/api/go-api/common/v1alpha"
	pkg "github.com/limejuice-cc/api/go-api/packaging/v1alpha"
)

type baseBuiltFile struct {
	name     string
	user     string
	group    string
	body     []byte
	mode     os.FileMode
	fileType pkg.FileType
}

func (f *baseBuiltFile) Name() string {
	return f.name
}

func (f *baseBuiltFile) User() string {
	return f.user
}
func (f *baseBuiltFile) Group() string {
	return f.group
}

func (f *baseBuiltFile) Body() []byte {
	return f.body
}

func (f *baseBuiltFile) Size() int {
	return len(f.body)
}

func (f *baseBuiltFile) Mode() os.FileMode {
	return f.mode
}

func (f *baseBuiltFile) Type() pkg.FileType {
	return f.fileType
}

// NewBuiltFile creates a new built file
func NewBuiltFile(r io.Reader, name, user, group string, mode os.FileMode, fileType pkg.FileType) (specs.BuiltFile, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return &baseBuiltFile{
		name:     name,
		user:     user,
		group:    group,
		body:     body,
		mode:     mode,
		fileType: fileType,
	}, nil
}

type baseBuildRequestOutput struct {
	files []specs.BuiltFile
}

// NewBuildRequestOutput creates a new BuildRequestOutput
func NewBuildRequestOutput() (specs.BuildRequestOutput, error) {
	return &baseBuildRequestOutput{files: []specs.BuiltFile{}}, nil
}

func (o *baseBuildRequestOutput) Files() []specs.BuiltFile {
	return o.files
}

func (o *baseBuildRequestOutput) AddFile(file specs.BuiltFile) {
	o.files = append(o.files, file)
}

type baseBuildContext struct {
	architecture    common.Architecture
	operatingSystem common.OperatingSystem
}

func (c *baseBuildContext) Architecture() common.Architecture {
	return c.architecture
}

func (c *baseBuildContext) OperatingSystem() common.OperatingSystem {
	return c.operatingSystem
}

// NewBuildContext returns a new BuildContext
func NewBuildContext(architecture common.Architecture, operatingSystem common.OperatingSystem) (specs.BuildContext, error) {
	return &baseBuildContext{
		architecture:    architecture,
		operatingSystem: operatingSystem}, nil
}
