#!/usr/bin/tclsh
#
# Run this script to extract the error numbers that appear at the end of
# each log file entry from the source text.
#
set in [open althttpd.c r]
while {![eof $in]} {
  set line [gets $in]
  if {[regexp {(\d+)[^0-9]+/\* LOG: (.*) \*/} $line all num msg]} {
    puts "INSERT INTO xref VALUES($num,'$msg');"
  }
}
close $in
