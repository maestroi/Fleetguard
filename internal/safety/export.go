package safety

// CheckRootOwnedFile rejects untrusted config, key and credential paths
// before a privileged enforcement process reads local authority files.
func CheckRootOwnedFile(path string) error {
 return checkRootPath(path,false)
}
