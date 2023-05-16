package dpkg

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"

	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.DpkgPostHandler, newDpkgHandler)
}

const version = 1

type dpkgHook struct {
	keepSystemInstalledFiles bool
}

func newDpkgHandler(a artifact.Option) (handler.PostHandler, error) {
	return dpkgHook{
		keepSystemInstalledFiles: a.KeepSystemInstalledFiles,
	}, nil
}

// Handle merges adds installed files to analysis result package info.
func (h dpkgHook) Handle(_ context.Context, r *analyzer.AnalysisResult, _ *types.BlobInfo) error {
	if !h.keepSystemInstalledFiles || r.OS.Family != os.Debian && r.OS.Family != os.Ubuntu {
		return nil
	}
	for i, pkgInfo := range r.PackageInfos {
		for j, pkg := range pkgInfo.Packages {
			if len(pkg.SystemInstalledFiles) == 0 {
				installedFiles, found := r.SystemInstalledFiles[pkg.Name+":"+pkg.Arch]
				if !found {
					installedFiles, found = r.SystemInstalledFiles[pkg.Name]
				}
				if found {
					r.PackageInfos[i].Packages[j].SystemInstalledFiles = installedFiles
				}
			}
		}
	}

	return nil
}

func (h dpkgHook) Version() int {
	return version
}

func (h dpkgHook) Type() types.HandlerType {
	return types.DpkgPostHandler
}

func (h dpkgHook) Priority() int {
	return types.DpkgPostHandlerPriority
}
