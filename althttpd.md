The Althttpd Webserver
======================

Althttpd is a simple webserver that has run the <https://sqlite.org/> website
since 2004.  Althttpd strives for simplicity, security, and low resource
usage.

As of 2022, the althttpd instance for sqlite.org answers
about 500,000 HTTP requests per day (about 5 or 6 per second)
delivering about 200GB of content per day (about 18 megabits/second) 
on a $40/month [Linode](https://www.linode.com/pricing).  The load 
average on this machine normally stays around 0.5.  About 10%
of the HTTP requests are CGI to various [Fossil](https://fossil-scm.org/)
source-code repositories.

Design Philosophy
----------------

Althttpd is usually launched from 
[xinetd](https://en.wikipedia.org/wiki/Xinetd) or
similar. A separate process is started for each incoming
connection, and that process is wholly focused on serving that
one connection.  A single althttpd
process will handle one or more HTTP requests over the same connection.
When the connection closes, the althttpd process exits.

Althttpd can also operate stand-alone. Althttpd itself listens on port
80 for incoming HTTP requests (or 443 for incoming HTTPS requests),
then forks a copy of itself to handle each inbound connection.  Each
connection is still handled using a separate process.  The only
difference is that the connection-handler process is now started by a
master althttpd instance rather than by xinetd.

Althttpd has no configuration file. All configuration is handled
using a few command-line arguments. This helps to keep the
configuration simple and mitigates worries about about introducing
a security vulnerability through a misconfigured web server.

Because each althttpd process only needs to service a single
connection, althttpd is single threaded.  Furthermore, each process
only lives for the duration of a single connection, which means that
althttpd does not need to worry too much about memory leaks.
These design factors help keep the althttpd source code simple,
which facilitates security auditing and analysis.

For serving TLS connections there are two options:

1. althttpd can be built with the `ENABLE_TLS` macro defined and linked to
`-lssl -lcrypto`, then started with the `--cert fullchain.pem` and
`--pkey privkey.pem` flags.

2. althttpd can be started via an external connection service such as
stunnel4, passing the `-https 1` flag to althttpd to tell it that it is
"indirectly" operating in HTTPS mode via that service.


Source Code
-----------

The complete source code for althttpd is contained within a single
C-code file with no dependences outside of the standard C library.
The source code file is named "[althttpd.c](/file/althttpd.c)".
To build and install althttpd, run the following command:

>
     gcc -Os -o /usr/bin/althttpd althttpd.c

The althttpd source code is heavily commented and accessible.
It should be relatively easy to customize for specialized needs.

To build althttpd with built-in TLS support using libssl:

>
    gcc -Os -o /usr/bin/althttpd -fPIC -DENABLE_TLS \
    althttpd.c -lssl -lcrypto


Setup Using Xinetd
------------------

Shown below is the complete text of the /etc/xinetd.d/http file on
sqlite.org that configures althttpd to server unencrypted
HTTP requests on both IPv4 and IPv6.
You can use this as a template to create your own installations.

> ~~~
service http
{
  port = 80
  flags = IPv4
  socket_type = stream
  wait = no
  user = root
  server = /usr/bin/althttpd
  server_args = -logfile /logs/http.log -root /home/www -user www-data
  bind = 45.33.6.223
}
service http
{
  port = 80
  flags = REUSE IPv6
  bind = 2600:3c00::f03c:91ff:fe96:b959
  socket_type = stream
  wait = no
  user = root
  server = /usr/bin/althttpd
  server_args = -logfile /logs/http.log -root /home/www -user www-data
}
~~~
    

The key observation here is that each incoming TCP/IP connection on 
port 80 launches a copy of /usr/bin/althttpd with some additional
arguments that amount to the configuration for the webserver.

Notice that althttpd is run as the superuser. This is not required, but if it
is done, then althttpd will move itself into a chroot jail at the root
of the web document hierarchy (/home/www in the example) and then drop
all superuser privileges prior to reading any content off of the wire.
The -user option tells althttpd to become user www-data after entering
the chroot jail.

The -root option tells althttpd where to find the document hierarchy.
In the case of sqlite.org, all content is served from /home/www.
At the top level of this document hierarchy is a bunch of directories
whose names end with ".website".  Each such directory is a separate
website.  The directory is chosen based on the Host: parameter of the
incoming HTTP request.  A partial list of the directories on sqlite.org
is this:

>
    3dcanvas_tcl_lang_org.website
    3dcanvas_tcl_tk.website
    androwish_org.website
    canvas3d_tcl_lang_org.website
    canvas3d_tcl_tk.website
    cvstrac_org.website
    default.website
    fossil_scm_com.website
    fossil_scm_hwaci_com.website
    fossil_scm_org.website
    system_data_sqlite_org.website
    wapp_tcl_lang_org.website
    wapp_tcl_tk.website
    www2_alt_mail_net.website
    www_androwish_org.website
    www_cvstrac_org.website
    www_fossil_scm_com.website
    www_fossil_scm_org.website
    www_sqlite_org.website
    
For each incoming HTTP request, althttpd takes the text of the Host:
parameter in the request header, converts it to lowercase, and changes
all characters other than ASCII alphanumerics into "_".  The result
determines which subdirectory to use for content.  If nothing matches,
the "default.website" directory is used as a fallback.

For example, if the Host parameter is "www.SQLite.org" then the name is
translated into "www\_sqlite\_org.website" and that is the directory
used to serve content.  If the Host parameter is "fossil-scm.org" then
the "fossil\_scm\_org.website" directory is used.  Oftentimes, two or
more names refer to the same website.  For example, fossil-scm.org,
www.fossil-scm.org, fossil-scm.com, and www.fossil-scm.com are all the
same website.  In that case, typically only one of the directories is
a real directory and the others are symbolic links.

On a minimal installation that only hosts a single website, it suffices
to have a single subdirectory named "default.website".

Within the *.website directory, the file to be served is selected by
the HTTP request URI.  Files that are marked as executable are run
as CGI.  Non-executable files with a name that ends with ".scgi"
and that have content of the form "SCGI hostname port" relay an SCGI
request to hostname:port. All other non-executable files are delivered
as-is.

If the request URI specifies the name of a directory within *.website,
then althttpd appends "/home", "/index.html", and "/index.cgi", in
that order, looking for a match.

If a prefix of a URI matches the name of an executable file then that
file is run as CGI.  For as-is content, the request URI must exactly
match the name of the file.

For content delivered as-is, the MIME-type is deduced from the filename
extension using a table that is compiled into althttpd.

Supporting HTTPS using Xinetd
-----------------------------

Beginning with version 2.0 (2022-01-16), althttpd optionally support
TLS-encrypted connections.  Setting up an HTTPS website using Xinetd
is very similar to an HTTP website.  The appropriate configuration for
xinetd is a single file named "https" in the /etc/xinetd.d directory
with content like the following:

> ~~~
service https
{
  port = 443
  flags = IPv4
  socket_type = stream
  wait = no
  user = root
  server = /usr/bin/althttpd
  server_args = -logfile /logs/http.log -root /home/www -user www-data -cert /etc/letsencrypt/live/sqlite.org/fullchain.pem -pkey /etc/letsencrypt/live/sqlite.org/privkey.pem
  bind = 45.33.6.223
}
service https
{
  port = 443
  flags = REUSE IPv6
  bind = 2600:3c00::f03c:91ff:fe96:b959
  socket_type = stream
  wait = no
  user = root
  server = /usr/bin/althttpd
  server_args = -logfile /logs/http.log -root /home/www -user www-data -cert /etc/letsencrypt/live/sqlite.org/fullchain.pem -pkey /etc/letsencrypt/live/sqlite.org/privkey.pem
}
~~~

You will, of course, want to adjust pathnames and IP address so that they
are appropriate for your particular installation.

This https configuration file is the same as the previous http
configuration file with just a few changes:

   *   Change the service name from "http" to "https"
   *   Change the port number from 80 to 443
   *   Add -cert and -pkey options to althttpd so that it will know where
       to find the appropriate certificate and private-key.

After creating the new https configuration file, simply restart
xinetd (usually with the command "`/etc/init.d/xinetd restart`") and
immediately an HTTPS version of your existing website will spring into
existance.


Setup For HTTPS Using Stunnel4
------------------------------

Older versions of althttpd did not support encryption.  The recommended
way of encrypting website using althttpd was to
use [stunnel4](https://www.stunnel.org/).  This advice has now changed.
We now recommend that you update your althttpd to version 2.0 or later
and use the xinetd technique described in the previous section.  This
section is retained for historical reference.

On the sqlite.org website, the relevant lines of the
/etc/stunnel/stunnel.conf file are:

> ~~~
cert = /etc/letsencrypt/live/sqlite.org/fullchain.pem
key = /etc/letsencrypt/live/sqlite.org/privkey.pem
[https]
accept       = :::443
TIMEOUTclose = 0
exec         = /usr/bin/althttpd
execargs     = /usr/bin/althttpd -logfile /logs/http.log -root /home/www -user www-data -https 1
~~~

This setup is very similar to the xinetd setup.  One key difference is
the "-https 1" option is used to tell althttpd that the connection is
encrypted.  This is important so that althttpd will know to set the
HTTPS environment variable for CGI programs.

It is ok to have both xinetd and stunnel4 both configured to
run althttpd, at the same time. In fact, that is the way that the
SQLite.org website works.  Requests to <http://sqlite.org/> go through
xinetd and requests to <https://sqlite.org/> go through stunnel4.

Stand-alone Operation
---------------------

On the author's desktop workstation, in his home directory is a subdirectory
named ~/www/default.website.  That subdirectory contains a collection of
files and CGI scripts.  Althttpd can serve the content there by running
the following command:

> ~~~
althttpd -root ~/www -port 8080
~~~

The "-port 8080" option is what tells althttpd to run in stand-alone
mode, listening on port 8080.

The author of althttpd has only ever used stand-alone mode for testing.
Since althttpd does not itself support TLS encryption, the
stunnel4 setup is preferred for production websites.

Stand-alone with HTTPS
----------------------

If althttpd is built with TLS support then it can be told to operate
in HTTPS mode with one of the following options:

> ~~~
althttpd -root ~/www --port 8043 --cert unsafe-builtin
~~~

this option uses a compiled-in self-signed SSL certificate
**which is wildly insecure** and is intended for testing purposes
only.  Use the --cert option to specify your own PEM-format SSL
certificate.  The argument to --cert can be the concatenation of
the SSL private key (often named "privkey.pem") and the certificate
chain (often named "fullchain.pem").  Alternatively, the --cert
can point to just the fullchain.pem file and the separate --pkey
option can point to the privkey.pem file.

Using your own certificate:

> ~~~
althttpd -root ~/www --port 8043 --cert fullchain.pem --pkey privkey.pem
~~~

Note that the certificate is read before althttpd drops root
privileges, so the certificate may live somewhere inaccessible to
the non-root user under which the althttpd process will run.


Security Features
-----------------

To defend against mischief, there are restrictions on names of files that
althttpd will serve.  Within the request URI, all characters other than
alphanumerics and ",-./:~" are converted into a single "_".  Furthermore,
if any path element of the request URI begins with "." or "-" then
althttpd always returns a 404 Not Found error.  Thus it is safe to put
auxiliary files (databases or other content used by CGI, for example)
in the document hierarchy as long as the filenames being with "." or "-".

When althttpd returns a 404, it tries to determine whether the request
is malicous and, if it believes so, it may optionally [temporarily
block the client's IP](#ipshun).

An exception:  Though althttpd normally returns 404 Not Found for any
request with a path element beginning with ".", it does allow requests
where the URI begins with "/.well-known/".  File or directory names
below "/.well-known/" are allowed to begin with "." or "-" (but not
with "..").  This exception is necessary to allow LetsEncrypt to validate
ownership of the website.

Basic Authentication
--------------------

If a file named "-auth" appears anywhere within the content hierarchy,
then all sibling files and all files in lower-level directories require
[HTTP basic authentication](https://en.wikipedia.org/wiki/Basic_access_authentication),
as defined by the content of the "-auth" file.
The "-auth" file is plain text and line oriented.
Blank lines and lines that begin with "#" are ignored.
Other lines have meaning as follows:

  *  <b>http-redirect</b>

     The http-redirect line, if present, causes all HTTP requests to
     redirect into an HTTPS request.  The "-auth" file is read and
     processes sequentially, so lines below the "http-redirect" line
     are never seen or processed for http requests.

  *  <b>https-only</b>

     The https-only line, if present, means that only HTTPS requests
     are allowed.  Any HTTP request results in a 404 Not Found error.
     The https-only line normally occurs after an http-redirect line.

  *  <b>realm</b> <i>NAME</i>

     A single line of this form establishes the "realm" for basic
     authentication.  Web browsers will normally display the realm name
     as a title on the dialog box that asks for username and password.

  *  <b>user</b> <i>NAME LOGIN:PASSWORD</i>

     There are multiple user lines, one for each valid user.  The
     LOGIN:PASSWORD argument defines the username and password that
     the user must type to gain access to the website.  The password
     is clear-text - HTTP Basic Authentication is not the most secure
     authentication mechanism.  Upon successful login, the NAME is
     stored in the REMOTE_USER environment variable so that it can be
     accessed by CGI scripts.  NAME and LOGIN are usually the same,
     but can be different.

  *  <b>anyone</b>

     If the "anyone" line is encountered, it means that any request is
     allowed, even if there is no username and password provided.
     This line is useful in combination with "http-redirect" to cause
     all ordinary HTTP requests to redirect to HTTPS without requiring
     login credentials.

Basic Authentication Examples
-----------------------------

The <http://www.sqlite.org/> website contains a "-auth" file in the
toplevel directory as follows:

>
     http-redirect
     anyone

That -auth file causes all HTTP requests to be redirected to HTTPS, without
requiring any further login.  (Try it: visit http://sqlite.org/ and
verify that you are redirected to https://sqlite.org/.)

There is a "-auth" file at <https://fossil-scm.org/private/> that looks
like this:

>
     realm Access To All Fossil Repositories
     http-redirect
     user drh drh:xxxxxxxxxxxxxxxx

Except, of course, the password is not a row of "x" characters.  This
demonstrates the typical use for a -auth file.  Access is granted for
a single user to the content in the "private" subdirectory, provided that
the user enters with HTTPS instead of HTTP.  The "http-redirect" line
is strongly recommended for all basic authentication since the password
is contained within the request header and can be intercepted and
stolen by bad guys if the request is sent via HTTP.

Log File
--------

If the -logfile option is given on the althttpd command-line, then a single
line is appended to the named file for each HTTP request.
The log file is in the Comma-Separated Value or CSV format specified
by [RFC4180](https://tools.ietf.org/html/rfc4180).
There is a comment in the source code that explains what each of the fields
in this output line mean.

The fact that the log file is CSV makes it easy to import into
SQLite for analysis, using a script like this:

>
    CREATE TABLE log(
      date TEXT,             /* Timestamp */
      ip TEXT,               /* Source IP address */
      url TEXT,              /* Request URI */
      ref TEXT,              /* Referer */
      code INT,              /* Result code.  ex: 200, 404 */
      nIn INT,               /* Bytes in request */
      nOut INT,              /* Bytes in reply */
      t1 INT, t2 INT,        /* Process time (user, system) milliseconds */
      t3 INT, t4 INT,        /* CGI script time (user, system) milliseconds */
      t5 INT,                /* Wall-clock time, milliseconds */
      nreq INT,              /* Sequence number of this request */
      agent TEXT,            /* User agent */
      user TEXT,             /* Remote user */
      n INT,                 /* Bytes of url that are in SCRIPT_NAME */
      lineno INT             /* Source code line that generated log entry */
    );
    .mode csv
    .import httplog.csv log
    

The filename on the -logfile option may contain time-based characters 
that are expanded by [strftime()](https://linux.die.net/man/3/strftime).
Thus, to cause a new logfile to be used for each day, you might use
something like:

>
     -logfile /var/logs/althttpd/httplog-%Y%m%d.csv


<a id="ipshun"></a>
Client IP Blocking
------------------

If the `--ipshun DIRECTORY` option is included to althttpd and
DIRECTORY is an absolute pathname (begins with "/") accessible from
within the chroot jail, and if the IP address of the client appears as
a file within that directory, then althttpd might return 503 Service
Unavailable rather than process the request.

*  If the file is zero bytes in size, then 503 is always returned.
   Thus you can "touch" a file that is an IP address name to
   permanently banish that client.

*  If the file is N bytes in size, then 503 is returned if the mtime
   of the file is less than 60*N seconds ago.  In other words, the
   client is banished for one minute per byte in the file.

Banishment files are automatically created if althttpd gets a request
that would have resulted in a 404 Not Found, and upon examining the
REQUEST_URI the request looks suspicious. Any request that include
/../ is considered a hack attempt, for example. There are other common
vulnerability probes that are also checked. Probably this list of
vulnerability probes will grow with experience.

The banishment files are automatically unlinked after 5 minutes/byte.

Banishment files are initially 1 byte in size. But if a banishment
expires and then a new request arrives prior to 5 minutes per byte of
block-file size, then the file grows by one byte and the mtime is
reset.

<a id="gzip"></a>
GZip Content Compression
------------------------

Althttpd has basic support for server-side content compression, which
often reduces the over-the-wire cost of files by more than half.
Rather than add a dependency on a compression library to althttpd, it
relies on the client to provide content in both compressed and
uncompressed forms.

When serving a file, if the client expresses support for gzip
compression and a file with the same name plus a `.gz` extension is
found, the gzipped copy of the file is served to the client with a
response header indicating that it is gzipped. To the user, it appears
as if the originally-requested file is served compressed. Under the
hood, however, a different file is served.

Note that this feature only supports static files, not CGI.
