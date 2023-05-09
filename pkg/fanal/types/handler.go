package types

type HandlerType string

const (
	SystemFileFilteringPostHandler HandlerType = "system-file-filter"
	UnpackagedPostHandler          HandlerType = "unpackaged"
	DpkgPostHandler                HandlerType = "dpkg"

	// SystemFileFilteringPostHandlerPriority should be higher than other handlers.
	// Otherwise, other handlers need to process unnecessary files.
	SystemFileFilteringPostHandlerPriority = 100

	UnpackagedPostHandlerPriority = 50
	DpkgPostHandlerPriority       = 50
)
