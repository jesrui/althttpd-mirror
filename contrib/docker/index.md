# Building Static Althttpd using Docker

Building purely static binaries on Linux platforms which use glibc
(i.e. most Linux platforms) is not always possible because glibc
cannot statically link certain components. It will create what is
ostensibly a static binary but will require dynamically-loadable
components (with the proper versions) at runtime.

One way around that is to build on a system which uses a libc which
doesn't have that limitation. [Alpine
Linux](https://www.alpinelinux.org/) uses [such a
libc](https://musl.libc.org/) and is readily available for use via
[Docker](https://docker.io).

This directory contains a Docker control file and a shell script which
use docker to build static copies of althttpd from its trunk version.
They require, of course, docker, and that the user running them be in
the `docker` user group. With those prerequisites met, simply run:

>
    $ ./build-static-althttpd.sh

The result, if it succeeds, will be one or more static binaries
in the current directory.
