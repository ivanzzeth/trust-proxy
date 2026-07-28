package credentials

// Windows has no O_NOFOLLOW, so the open flag is a no-op there.
//
// Not a silent gap: the threat this guards against is `install --claim-for
// <another account>` running as root, and that whole path is Unix-shaped —
// SUDO_USER, home directories owned by other users, Lchown. On Windows the same
// concern is an ACL question, and the audit already records that as unverified
// (nothing there has run on real hardware). O_EXCL still applies on both, so a
// pre-existing tmp file is refused rather than written through either way.
const noFollow = 0
