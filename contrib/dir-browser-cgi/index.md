# Basic Dir-Browser CGI Script

Althttpd does not offer directory-browsing features (nor should it),
but they can be easily added on a per-directory basis using a CGI
script.

This directory houses one basic solution to the problem. In short:

- Put `dir-index.sh` in some path accessible by the althttpd instance,
  taking its chroot behavior into account. This file need not be
  executable, nor must it live in a directory under the current site's
  web root.

- In each browseable directory, place a copy of `index`, adjusting the
  path to `dir-index.sh` to suit the site.

See the comments in `dir-index.sh` for its configurable options and
hack it to suit site-specific preferences such as look and feel, or to
add script-driven features such as sortable table columns.

**BSD users:** as written, `dir-index.sh` assumes GNU-compatible
versions of commands like `date` and `stat` and requires modification
in order to run on systems which don't use those versions.
