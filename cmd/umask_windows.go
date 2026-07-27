package cmd

// Windows has no umask; file access there is decided by the inherited ACL of the
// containing directory. That is a real gap rather than a non-issue — %ProgramData%
// grants authenticated users create-file rights, and the managed binary lives
// inside the data directory on Windows — but it needs an ACL, not a mode bit, and
// no Windows machine has verified any of this yet.
func tightenUmask() {}
