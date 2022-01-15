########################################################################
# Basic dir-browser CGI script. Intended usage:
#
# - Put this file somewhere accessible by the web server process. It
#   need not be executable nor in the web root.
#
# - In each browseable directory, add an 'index' CGI shell script
#   which simply sources this file and does nothing else afterwards.
#
# - Tweak this file to suit your site's preferences.
#
########################################################################
#
# The following environment vars can be set before sourcing this
# file to influence its output:
#
#  - DIR_INDEX_PARENT=1 adds ".." to the list of dirs.
#
#  - DIR_INDEX_ONLY_DIRS=1 only shows dirs, not files.
#
#  - DIR_INDEX_ONLY_FILES=1 only shows files, not dirs.
#
# By default .. is not shown and both files and dirs are.
#
########################################################################
#
# ACHTUNG BSD USERS: this script is (or was originally) written
# for use on systems which use the GNU coreutils and requires
# flags for some commands which are not availabe on their non-GNU
# counterparts.
#
########################################################################
#
# Maintenance reminder: this script "really should" be limited to
# commands which are built in to busybox so that it can be run from
# within a chroot jail without any additional binaries.
#
########################################################################
echo "Content-type: text/html"
echo

cat <<EOF
<html><body><style>
td { margin: 0 }
th, td { text-align: left; padding: 0.25em 2em 0.5em 0.25em; }
tbody > tr:nth-child(odd) {
  background-color: #f2f2f2;
}
table {
  /*margin-left: auto;
  margin-right: auto;*/
  /*width: 80%;*/
  font-family: monospace;
}
thead > th:nth-child(1) { width: 50% }
thead > th:nth-child(2) { }
</style>
EOF

echo "<header><h1>${REQUEST_URI}</h1></header>"

echo "<table><thead><th>File/[Dir]</th><th>Size</th><th>Timestamp</th></thead><tbody>"
if [ x1 = x${DIR_INDEX_PARENT} ];then
    echo "<tr><td>[<a href='..'>..</a>]</td><td></td><td></td></tr>"
fi
for i in [a-zA-Z]*[a-zA-Z_]; do
    test "$i" = "index" && continue
    echo -n "<tr>"
    if test -d $i; then
        if test x1 != "x${DIR_INDEX_ONLY_FILES-0}"; then
            echo -n "<td>[<a href='$i'>$i</a>]</td><td></td>"
        fi
    else
        if test x1 != "x${DIR_INDEX_ONLY_DIRS-0}"; then
            # On BSD:
            # s=$(stat -c %z "$i")
            # On GNU/Linux:
            s=$(stat -c '%s' "$i")
            echo -n "<td><a href='$i'>$i</a></td><td>$s bytes</td>"
        fi
    fi
    #t=$(stat -c '%y' $i | cut -c1-19)
    # GNU/Linux:
    t=$(date --reference "$i" +"%Y-%m-%d %H:%M:%S")
    # BSD ^^^^^^^^^^^^^^ equivalent?
    echo "<td>$t</td></tr>"
done
echo -n "</tbody></table>"

echo "</body></html>"
