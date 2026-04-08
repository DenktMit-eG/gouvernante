package lockfile

// PackageEntry represents a resolved package in a lockfile.
type PackageEntry struct {
	Name    string
	Version string
}

// Result holds parsed entries from one lockfile.
type Result struct {
	Name    string // display name (base filename or relative path)
	Path    string // original filesystem path used to parse the lockfile
	Entries []PackageEntry
}
