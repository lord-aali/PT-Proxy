package standalone

import "os"

// ManagedByTor reports whether the process was launched by Tor as a pluggable transport.
func ManagedByTor() bool {
	return os.Getenv("TOR_PT_MANAGED_TRANSPORT_VER") != ""
}
