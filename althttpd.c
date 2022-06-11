/*
** 2001-09-15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
**
** This source code file implements a small, simple, stand-alone HTTP
** server.  
**
** Features:
**
**     * Launched from inetd/xinetd/systemd, or as a stand-alone server
**     * One process per request
**     * Deliver static content or run CGI or SCGI
**     * Virtual sites based on the "Host:" property of the HTTP header
**     * Runs in a chroot jail
**     * Unified log file in a CSV format
**     * Small code base (this 1 file) to facilitate security auditing
**     * Simple setup - no configuration files to misconfigure
** 
** This file implements a small and simple but secure and effective web
** server.  There are no frills.  Anything that could be reasonably
** omitted has been.
**
** Setup rules:
**
**    (1) Launch as root from inetd/systemd like this:
**
**            althttpd -logfile logfile -root /home/www -user nobody
**
**        It will automatically chroot to /home/www and become user "nobody".
**        The logfile name should be relative to the chroot jail.
**
**    (2) Directories of the form "*.website" (ex: www_sqlite_org.website)
**        contain content.  The directory is chosen based on the HTTP_HOST
**        request header.  If there is no HTTP_HOST header or if the
**        corresponding host directory does not exist, then the
**        "default.website" is used.
**
**        In stand-alone mode (when the --port option is used) if neither
**        the HTTP_HOST.website nor "default.website" directories exist,
**        then files are served directly from the root directory.  In
**        one-require mode (when the --port option is not used) then an
**        error is raised if "default.website" does not exist.
**
**        If the HTTP_HOST header contains any charaters other than
**        [a-zA-Z0-9_.,*~/] then a 403 error is generated.
**
**    (3) Any file or directory whose name begins with "." or "-" is ignored,
**        except if the URL begins with "/.well-known/" then initial "." and
**        "-" characters are allowed, but not initial "..".  The exception is
**        for RFC-5785 to allow letsencrypt or certbot to generate a TLS cert
**        using webroot.
**
**    (4) Characters other than [0-9a-zA-Z,-./:_~] and any %HH characters
**        escapes in the filename are all translated into "_".  This is
**        a defense against cross-site scripting attacks and other mischief.
**
**    (5) Executable files are run as CGI.  Files whose name ends with ".scgi"
**        trigger an SCGI request (see item 9 below).  All other files
**        are delivered as is.
**
**    (6) If a file named "-auth" exists in the same directory as the file to
**        be run as CGI/SCGI or to be delivered, then it contains information
**        for HTTP Basic authorization.  See file format details below.
**
**    (7) To run as a stand-alone server, simply add the "-port N" command-line
**        option to define which TCP port to listen on.  If the argument is
**        "--port N1..N2" then TCP ports between N1 and N2 are scanned looking
**        for one that is open and the first open port is used.
**
**    (8) For static content, the mimetype is determined by the file suffix
**        using a table built into the source code below.  If you have
**        unusual content files, you might need to extend this table.
**
**    (9) Content files that end with ".scgi" and that contain text of the
**        form "SCGI hostname port" will format an SCGI request and send it
**        to hostname:port, then relay back the reply.  Error behavior is
**        determined by subsequent lines of the .scgi file.  See SCGI below
**        for details.
**
**   (10) If compiled with -DENABLE_TLS and linked against OpenSSL and
**        launched with a --cert option to identify a certificate file, then
**        TLS is used to encrypt the connection.
**
** Command-line Options:
**
**  --root DIR       Defines the directory that contains the various
**                   $HOST.website subdirectories, each containing web content 
**                   for a single virtual host.  If launched as root and if
**                   "--user USER" also appears on the command-line and if
**                   "--jail 0" is omitted, then the process runs in a chroot
**                   jail rooted at this directory and under the userid USER.
**                   This option is required for xinetd launch but defaults
**                   to "." for a stand-alone web server.
**
**  --port N         Run in standalone mode listening on TCP port N, or from
**  --port N1..N2    the first available TCP port in the range from N1 to N2.
**
**  --user USER      Define the user under which the process should run if
**                   originally launched as root.  This process will refuse to
**                   run as root (for security).  If this option is omitted and
**                   the process is launched as root, it will abort without
**                   processing any HTTP requests.
**
**  --logfile FILE   Append a single-line, CSV-format, log file entry to FILE
**                   for each HTTP request.  FILE should be a full pathname.
**                   The FILE name is interpreted inside the chroot jail.  The
**                   FILE name is expanded using strftime() if it contains
**                   at least one '%' and is not too long.
**
**  --ipshun DIR     If the remote IP address is also the name of a file
**                   in DIR that has size N bytes and where either N is zero
**                   or the m-time of the file is less than N time-units ago
**                   then that IP address is being shunned and no requests
**                   are processed.  The time-unit is a compile-time option
**                   (BANISH_TIME) that defaults to 300 seconds.  If this
**                   happens, the client gets a 503 Service Unavailable
**                   reply. Furthermore, althttpd will create ip-shunning
**                   files following a 404 Not Found error if the request
**                   URI is an obvious hack attempt.
**
**  --https BOOLEAN  Indicates that input is coming over SSL and is being
**                   decoded upstream, perhaps by stunnel. This option
**                   does *not* activate built-in TLS support.  Use --cert
**                   for that.
**
**  --page NAME      Come up in stand-alone mode, and then try to launch a
**                   web-browser pointing to the NAME document after the
**                   listening socket has been created.  This option
**                   implies --loopback and "--port 8080..8100".
**
**  --loopback       Only accept loop-back TCP connections (connections
**                   originating from the same host).  This is the
**                   default if --root is omitted.
**
**  --family ipv4    Only accept input from IPV4 or IPV6, respectively.
**  --family ipv6    These options are only meaningful if althttpd is run
**                   as a stand-alone server.
**
**  --jail BOOLEAN   Indicates whether or not to form a chroot jail if 
**                   initially run as root.  The default is true, so the only
**                   useful variant of this option is "--jail 0" which prevents
**                   the formation of the chroot jail.
**
**  --max-age SEC    The value for "Cache-Control: max-age=%d".  Defaults to
**                   120 seconds.
**
**  --max-cpu SEC    Maximum number of seconds of CPU time allowed per
**                   HTTP connection.  Default 30 (build option:
**                   -DMAX_CPU=integer). 0 means no limit.
**
**  --debug BOOLEAN  Disables input timeouts.  This is useful for debugging
**                   when inputs are being typed in manually.
**
** Additional command-line options available when compiling with ENABLE_TLS:
**
**  --cert FILE      The TLS certificate, the "fullchain.pem" file
**
**  --pkey FILE      The TLS private key, the "privkey.pem" file.  May be
**                   omitted if the --cert file is the concatenation of
**                   the fullchain.pem and the privkey.pem.
**
**
** Command-line options can take either one or two initial "-" characters.
** So "--debug" and "-debug" mean the same thing, for example.
**
**
** Security Features:
**
** (1)  This program automatically puts itself inside a chroot jail if
**      it can and if not specifically prohibited by the "--jail 0"
**      command-line option.  The root of the jail is the directory that
**      contains the various $HOST.website content subdirectories.
**
** (2)  No input is read while this process has root privileges.  Root
**      privileges are dropped prior to reading any input (but after entering
**      the chroot jail, of course).  If root privileges cannot be dropped
**      (for example because the --user command-line option was omitted or
**      because the user specified by the --user option does not exist), 
**      then the process aborts with an error prior to reading any input.
**
** (3)  The length of an HTTP request is limited to MAX_CONTENT_LENGTH bytes
**      (default: 250 million).  Any HTTP request longer than this fails
**      with an error. (Build option: -DMAX_CONTENT_LENGTH=integer)
**
** (4)  There are hard-coded time-outs on each HTTP request.  If this process
**      waits longer than the timeout for the complete request, or for CGI
**      to finish running, then this process aborts.  (The timeout feature
**      can be disabled using the --debug command-line option.)
**
** (5)  If the HTTP_HOST request header contains characters other than
**      [0-9a-zA-Z,-./:_~] then the entire request is rejected.
**
** (6)  Any characters in the URI pathname other than [0-9a-zA-Z,-./:_~]
**      are converted into "_".  This applies to the pathname only, not
**      to the query parameters or fragment.
**
** (7)  If the first character of any URI pathname component is "." or "-"
**      then a 404 Not Found reply is generated.  This prevents attacks
**      such as including ".." or "." directory elements in the pathname
**      and allows placing files and directories in the content subdirectory
**      that are invisible to all HTTP requests, by making the first 
**      character of the file or subdirectory name "-" or ".".
**
** (8)  The request URI must begin with "/" or else a 404 error is generated.
**
** (9)  This program never sets the value of an environment variable to a
**      string that begins with "() {".
**
** Security Auditing:
**
** This webserver mostly only serves static content.  Any security risk will
** come from CGI and SCGI.  To check an installation for security, then, it
** makes sense to focus on the CGI and SCGI scripts.
**
** To locate all CGI files:
**
**          find *.website -executable -type f -print
**     OR:  find *.website -perm +0111 -type f -print
**
** The first form of the "find" command is preferred, but is only supported
** by GNU find.  On a Mac, you'll have to use the second form.
**
** To find all SCGI files:
**
**          find *.website -name '*.scgi' -type f -print
**
** If any file is a security concern, it can be disabled on a live
** installation by turning off read permissions:
**
**          chmod 0000 file-of-concern
**
** SCGI Specification Files:
**
** Content files (files without the execute bit set) that end with ".scgi"
** specify a connection to an SCGI server.  The format of the .scgi file
** follows this template:
**
**      SCGI hostname port
**      fallback: fallback-filename
**      relight: relight-command
**
** The first line specifies the location and TCP/IP port of the SCGI
** server that will handle the request.  Subsequent lines determine
** what to do if the SCGI server cannot be contacted.  If the
** "relight:" line is present, then the relight-command is run using
** system() and the connection is retried after a 1-second delay.  Use
** "&" at the end of the relight-command to run it in the background.
** Make sure the relight-command does not generate output, or that
** output will become part of the SCGI reply.  Add a ">/dev/null"
** suffix (before the "&") to the relight-command if necessary to
** suppress output.  If there is no relight-command, or if the relight
** is attempted but the SCGI server still cannot be contacted, then
** the content of the fallback-filename file is returned as a
** substitute for the SCGI request.  The mimetype is determined by the
** suffix on the fallback-filename.  The fallback-filename would
** typically be an error message indicating that the service is
** temporarily unavailable.
**
** Basic Authorization:
**
** If the file "-auth" exists in the same directory as the content file
** (for both static content and CGI) then it contains the information used
** for basic authorization.  The file format is as follows:
**
**    *  Blank lines and lines that begin with '#' are ignored
**    *  "http-redirect" forces a redirect to HTTPS if not there already
**    *  "https-only" disallows operation in HTTP
**    *  "user NAME LOGIN:PASSWORD" checks to see if LOGIN:PASSWORD 
**       authorization credentials are provided, and if so sets the
**       REMOTE_USER to NAME.
**    *  "realm TEXT" sets the realm to TEXT.
**
** There can be multiple "user" lines.  If no "user" line matches, the
** request fails with a 401 error.
**
** Because of security rule (7), there is no way for the content of the "-auth"
** file to leak out via HTTP request.
*/
#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <time.h>
#include <sys/times.h>
#include <netdb.h>
#include <errno.h>
#include <sys/resource.h>
#include <signal.h>
#include <dirent.h>
#ifdef linux
#include <sys/sendfile.h>
#endif
#include <assert.h>

/*
** Configure the server by setting the following macros and recompiling.
*/
#ifndef DEFAULT_PORT
#define DEFAULT_PORT "80"             /* Default TCP port for HTTP */
#endif
#ifndef MAX_CONTENT_LENGTH
#define MAX_CONTENT_LENGTH 250000000  /* Max length of HTTP request content */
#endif
#ifndef MAX_CPU
#define MAX_CPU 30                    /* Max CPU cycles in seconds */
#endif

#ifndef ALTHTTPD_VERSION
#define ALTHTTPD_VERSION "2.0"
#endif

#ifndef BANISH_TIME
#define BANISH_TIME 300               /* How long to banish for abuse (sec) */
#endif

#ifndef SERVER_SOFTWARE
#  define SERVER_SOFTWARE "althttpd " ALTHTTPD_VERSION
#endif
#ifndef SERVER_SOFTWARE_TLS
#  ifdef ENABLE_TLS
#    define SERVER_SOFTWARE_TLS SERVER_SOFTWARE ", " OPENSSL_VERSION_TEXT
#  else
#    define SERVER_SOFTWARE_TLS SERVER_SOFTWARE
#  endif
#endif

/*
** We record most of the state information as global variables.  This
** saves having to pass information to subroutines as parameters, and
** makes the executable smaller...
*/
static const char *zRoot = 0;    /* Root directory of the website */
static char *zPostData= 0;       /* POST data */
static int nPostData = 0;        /* Number of bytes of POST data */
static char *zProtocol = 0;      /* The protocol being using by the browser */
static char *zMethod = 0;        /* The method.  Must be GET */
static char *zScript = 0;        /* The object to retrieve */
static char *zRealScript = 0;    /* The object to retrieve.  Same as zScript
                                 ** except might have "/index.html" appended */
static char *zRequestUri = 0;    /* Sanitized request uri */
static char *zHome = 0;          /* The directory containing content */
static char *zQueryString = 0;   /* The query string on the end of the name */
static char *zFile = 0;          /* The filename of the object to retrieve */
static int lenFile = 0;          /* Length of the zFile name */
static char *zDir = 0;           /* Name of the directory holding zFile */
static char *zPathInfo = 0;      /* Part of the pathname past the file */
static char *zAgent = 0;         /* What type if browser is making this query */
static char *zServerName = 0;    /* The name after the http:// */
static char *zServerPort = 0;    /* The port number */
static char *zServerSoftware = 0;/* Software name and version info */
static char *zCookie = 0;        /* Cookies reported with the request */
static char *zHttpHost = 0;      /* Name according to the web browser */
static char *zRealPort = 0;      /* The real TCP port when running as daemon */
static char *zRemoteAddr = 0;    /* IP address of the request */
static char *zReferer = 0;       /* Name of the page that refered to us */
static char *zAccept = 0;        /* What formats will be accepted */
static char *zAcceptEncoding =0; /* gzip or default */
static char *zContentLength = 0; /* Content length reported in the header */
static char *zContentType = 0;   /* Content type reported in the header */
static char *zQuerySuffix = 0;   /* The part of the URL after the first ? */
static char *zAuthType = 0;      /* Authorization type (basic or digest) */
static char *zAuthArg = 0;       /* Authorization values */
static char *zRemoteUser = 0;    /* REMOTE_USER set by authorization module */
static char *zIfNoneMatch= 0;    /* The If-None-Match header value */
static char *zIfModifiedSince=0; /* The If-Modified-Since header value */
static char *zHttpScheme = "http";/* HTTP_SCHEME CGI variable */
static char *zHttps = 0;         /* HTTPS CGI variable */
static int nIn = 0;              /* Number of bytes of input */
static int nOut = 0;             /* Number of bytes of output */
static char zReplyStatus[4];     /* Reply status code */
static int statusSent = 0;       /* True after status line is sent */
static const char *zLogFile = 0; /* Log to this file */
static const char *zIPShunDir=0; /* Directory containing hostile IP addresses */
static int debugFlag = 0;        /* True if being debugged */
static struct timeval beginTime; /* Time when this process starts */
static int closeConnection = 0;  /* True to send Connection: close in reply */
static int nRequest = 0;         /* Number of requests processed */
static int omitLog = 0;          /* Do not make logfile entries if true */
static int useHttps = 0;         /* 0=HTTP, 1=external HTTPS (stunnel),
                                 ** 2=builtin TLS support */
static int useTimeout = 1;       /* True to use times */
static int nTimeoutLine = 0;     /* Line number where timeout was set */
static int standalone = 0;       /* Run as a standalone server (no inetd) */
static int ipv6Only = 0;         /* Use IPv6 only */
static int ipv4Only = 0;         /* Use IPv4 only */
static struct rusage priorSelf;  /* Previously report SELF time */
static struct rusage priorChild; /* Previously report CHILD time */
static int mxAge = 120;          /* Cache-control max-age */
static char *default_path = "/bin:/usr/bin";  /* Default PATH variable */
static char *zScgi = 0;          /* Value of the SCGI env variable */
static int rangeStart = 0;       /* Start of a Range: request */
static int rangeEnd = 0;         /* End of a Range: request */
static int maxCpu = MAX_CPU;     /* Maximum CPU time per process */

/* Forward reference */
static void Malfunction(int errNo, const char *zFormat, ...);



#ifdef ENABLE_TLS
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
typedef struct TlsServerConn {
  SSL *ssl;          /* The SSL codec */
  BIO *bio;          /* SSL BIO object */
  int iSocket;       /* The socket */
} TlsServerConn;

/*
** There can only be a single OpenSSL IO connection open at a time.
** State information about that IO is stored in the following
** global singleton:
*/
static struct TlsState {
  int isInit;             /* 0: uninit 1: init as client 2: init as server */
  SSL_CTX *ctx;
  const char *zCertFile;  /* --cert CLI arg */
  const char *zKeyFile;   /* --pkey CLI arg */
  TlsServerConn * sslCon;
} tlsState = {
  0,                      /* isInit */
  NULL,                   /* SSL_CTX *ctx */
  NULL,                   /* zCertFile */
  NULL,                   /* zKeyFile */
  NULL                    /* sslCon */
};

/*
** Read a single line of text from the client and stores it in zBuf
** (which must be at least nBuf bytes long). On error it
** calls Malfunction().
**
** If it reads anything, it returns zBuf.
*/
static char *tls_gets(void *pServerArg, char *zBuf, int nBuf){
  int n = 0, err = 0;
  int i;
  TlsServerConn * const pServer = (TlsServerConn*)pServerArg;
  if( BIO_eof(pServer->bio) ) return 0;
  for(i=0; i<nBuf-1; i++){
    n = SSL_read(pServer->ssl, &zBuf[i], 1);
    err = SSL_get_error(pServer->ssl, n);
    if( err!=0 ){
      Malfunction(525,"SSL read error.");
    }else if( 0==n || zBuf[i]=='\n' ){
      break;
    }
  }
  zBuf[i+1] = 0;
  return zBuf;
}

/*
** Reads up tp nBuf bytes of TLS-decoded bytes from the client and
** stores them in zBuf, which must be least nBuf bytes long.  Returns
** the number of bytes read. Fails fatally if nBuf is "too big" or if
** SSL_read() fails. Once pServerArg reaches EOF, this function simply
** returns 0 with no side effects.
*/
static size_t tls_read_server(void *pServerArg, void *zBuf, size_t nBuf){
  int err = 0;
  size_t rc = 0;
  TlsServerConn * const pServer = (TlsServerConn*)pServerArg;
  if( nBuf>0x7fffffff ){
    Malfunction(526,"SSL read too big"); /* LOG: SSL read too big */
  }
  while( 0==err && nBuf!=rc && 0==BIO_eof(pServer->bio) ){
    const int n = SSL_read(pServer->ssl, zBuf + rc, (int)(nBuf - rc));
    if( n==0 ){
      break;
    }
    err = SSL_get_error(pServer->ssl, n);
    if(0==err){
      rc += n;
    }else{
      Malfunction(527,"SSL read error."); /* LOG: SSL read error */
    }
  }
  return rc;
}

/*
** Write cleartext bytes into the SSL server codec so that they can
** be encrypted and sent back to the client. On success, returns
** the number of bytes written, else returns a negative value.
*/
static int tls_write_server(void *pServerArg, void const *zBuf,  size_t nBuf){
  int n;
  TlsServerConn * const pServer = (TlsServerConn*)pServerArg;
  if( nBuf<=0 ) return 0;
  if( nBuf>0x7fffffff ){
    Malfunction(528,"SSL write too big"); /* LOG: SSL write too big */
  }
  n = SSL_write(pServer->ssl, zBuf, (int)nBuf);
  if( n<=0 ){
    /* Do NOT call Malfunction() from here, as Malfunction()
    ** may output via this function. The current error handling
    ** is somewhat unsatisfactory, as it can lead to negative
    ** response length sizes in the althttpd log. */
    return -SSL_get_error(pServer->ssl, n);
  }else{
    return n;
  }
}
#endif /* ENABLE_TLS */

/*
** A printf() proxy which outputs either to stdout or the outbound TLS
** connection, depending on connection state. It uses a
** statically-sized buffer for TLS output and will fail (via
** Malfunction()) if it's passed too much data. In non-TLS mode it has
** no such limitation. The buffer is generously sized, in any case, to
** be able to handle all of the headers output by althttpd as of the
** time of this writing.
*/
#ifdef ENABLE_TLS
static int althttpd_vprintf(char const * fmt, va_list va){
  if( useHttps!=2 || NULL==tlsState.sslCon ){
    return vprintf(fmt, va);
  }else{
    char pfBuffer[10000];
    const int sz = vsnprintf(pfBuffer, sizeof(pfBuffer), fmt, va);
    if( sz<(int)sizeof(pfBuffer) ){
      return (int)tls_write_server(tlsState.sslCon, pfBuffer, sz);
    }else{
      Malfunction(529, /* LOG: Output buffer too small */
         "Output buffer is too small. Wanted %d bytes.", sz);
      return 0;
    }
  }
}
#else
#define althttpd_vprintf vprintf
#endif

#ifdef ENABLE_TLS
static int althttpd_printf(char const * fmt, ...){
  int rc;
  va_list va;
  va_start(va,fmt);
  rc = althttpd_vprintf(fmt, va);
  va_end(va);
  return rc;
}
static void *tls_new_server(int iSocket);
static void tls_close_server(void *pServerArg);
static void tls_atexit(void);
#else
#define althttpd_printf printf
#endif


/* forward references */
static int tls_init_conn(int iSocket);
static void tls_close_conn(void);
static void althttpd_fflush(FILE *f);

/*
** Flush the buffer then exit.
*/
static void althttpd_exit(void){
  althttpd_fflush(stdout);
  tls_close_conn();
  exit(0);
}

/*
** Mapping between CGI variable names and values stored in
** global variables.
*/
static struct {
  char *zEnvName;
  char **pzEnvValue;
} cgienv[] = {
  { "CONTENT_LENGTH",           &zContentLength }, /* Must be first for SCGI */
  { "AUTH_TYPE",                &zAuthType },
  { "AUTH_CONTENT",             &zAuthArg },
  { "CONTENT_TYPE",             &zContentType },
  { "DOCUMENT_ROOT",            &zHome },
  { "HTTP_ACCEPT",              &zAccept },
  { "HTTP_ACCEPT_ENCODING",     &zAcceptEncoding },
  { "HTTP_COOKIE",              &zCookie },
  { "HTTP_HOST",                &zHttpHost },
  { "HTTP_IF_MODIFIED_SINCE",   &zIfModifiedSince },
  { "HTTP_IF_NONE_MATCH",       &zIfNoneMatch },
  { "HTTP_REFERER",             &zReferer },
  { "HTTP_SCHEME",              &zHttpScheme },
  { "HTTP_USER_AGENT",          &zAgent },
  { "HTTPS",                    &zHttps },
  { "PATH",                     &default_path },
  { "PATH_INFO",                &zPathInfo },
  { "QUERY_STRING",             &zQueryString },
  { "REMOTE_ADDR",              &zRemoteAddr },
  { "REQUEST_METHOD",           &zMethod },
  { "REQUEST_URI",              &zRequestUri },
  { "REMOTE_USER",              &zRemoteUser },
  { "SCGI",                     &zScgi },
  { "SCRIPT_DIRECTORY",         &zDir },
  { "SCRIPT_FILENAME",          &zFile },
  { "SCRIPT_NAME",              &zRealScript },
  { "SERVER_NAME",              &zServerName },
  { "SERVER_PORT",              &zServerPort },
  { "SERVER_PROTOCOL",          &zProtocol },
  { "SERVER_SOFTWARE",          &zServerSoftware },
};


/*
** Double any double-quote characters in a string.  This is used to
** quote strings for output into the CSV log file.
*/
static char *Escape(const char *z){
  size_t i, j;
  size_t n;
  char c;
  char *zOut;
  for(i=0; (c=z[i])!=0 && c!='"'; i++){}
  if( c==0 ) return (char *)z;
  n = 1;
  for(i++; (c=z[i])!=0; i++){ if( c=='"' ) n++; }
  zOut = malloc( i+n+1 );
  if( zOut==0 ) return "";
  for(i=j=0; (c=z[i])!=0; i++){
    zOut[j++] = c;
    if( c=='"' ) zOut[j++] = c;
  }
  zOut[j] = 0;
  return zOut;
}

/*
** Convert a struct timeval into an integer number of microseconds
*/
static long long int tvms(struct timeval *p){
  return ((long long int)p->tv_sec)*1000000 + (long long int)p->tv_usec;
}

/*
** Make an entry in the log file.  If the HTTP connection should be
** closed, then terminate this process.  Otherwise return.
*/
static void MakeLogEntry(int exitCode, int lineNum){
  FILE *log;
  if( zPostData ){
    free(zPostData);
    zPostData = 0;
  }
  if( zLogFile && !omitLog ){
    struct timeval now;
    struct tm *pTm;
    struct rusage self, children;
    int waitStatus;
    const char *zRM = zRemoteUser ? zRemoteUser : "";
    const char *zFilename;
    size_t sz;
    char zDate[200];
    char zExpLogFile[500];

    if( zScript==0 ) zScript = "";
    if( zRealScript==0 ) zRealScript = "";
    if( zRemoteAddr==0 ) zRemoteAddr = "";
    if( zHttpHost==0 ) zHttpHost = "";
    if( zReferer==0 ) zReferer = "";
    if( zAgent==0 ) zAgent = "";
    gettimeofday(&now, 0);
    pTm = localtime(&now.tv_sec);
    strftime(zDate, sizeof(zDate), "%Y-%m-%d %H:%M:%S", pTm);
    sz = strftime(zExpLogFile, sizeof(zExpLogFile), zLogFile, pTm);
    if( sz>0 && sz<sizeof(zExpLogFile)-2 ){
      zFilename = zExpLogFile;
    }else{
      zFilename = zLogFile;
    }
    waitpid(-1, &waitStatus, WNOHANG);
    getrusage(RUSAGE_SELF, &self);
    getrusage(RUSAGE_CHILDREN, &children);
    if( (log = fopen(zFilename,"a"))!=0 ){
#ifdef COMBINED_LOG_FORMAT
      strftime(zDate, sizeof(zDate), "%d/%b/%Y:%H:%M:%S %Z", pTm);
      fprintf(log, "%s - - [%s] \"%s %s %s\" %s %d \"%s\" \"%s\"\n",
              zRemoteAddr, zDate, zMethod, zScript, zProtocol,
              zReplyStatus, nOut, zReferer, zAgent);
#else
      strftime(zDate, sizeof(zDate), "%Y-%m-%d %H:%M:%S", pTm);
      /* Log record files:
      **  (1) Date and time
      **  (2) IP address
      **  (3) URL being accessed
      **  (4) Referer
      **  (5) Reply status
      **  (6) Bytes received
      **  (7) Bytes sent
      **  (8) Self user time
      **  (9) Self system time
      ** (10) Children user time
      ** (11) Children system time
      ** (12) Total wall-clock time
      ** (13) Request number for same TCP/IP connection
      ** (14) User agent
      ** (15) Remote user
      ** (16) Bytes of URL that correspond to the SCRIPT_NAME
      ** (17) Line number in source file
      */
      fprintf(log,
        "%s,%s,\"%s://%s%s\",\"%s\","
           "%s,%d,%d,%lld,%lld,%lld,%lld,%lld,%d,\"%s\",\"%s\",%d,%d\n",
        zDate, zRemoteAddr, zHttpScheme, Escape(zHttpHost), Escape(zScript),
        Escape(zReferer), zReplyStatus, nIn, nOut,
        tvms(&self.ru_utime) - tvms(&priorSelf.ru_utime),
        tvms(&self.ru_stime) - tvms(&priorSelf.ru_stime),
        tvms(&children.ru_utime) - tvms(&priorChild.ru_utime),
        tvms(&children.ru_stime) - tvms(&priorChild.ru_stime),
        tvms(&now) - tvms(&beginTime),
        nRequest, Escape(zAgent), Escape(zRM),
        (int)(strlen(zHttpScheme)+strlen(zHttpHost)+strlen(zRealScript)+3),
        lineNum
      );
      priorSelf = self;
      priorChild = children;
#endif
      fclose(log);
      nIn = nOut = 0;
    }
  }
  if( closeConnection ){
    exit(exitCode);
  }
  statusSent = 0;
}

/*
** Allocate memory safely
*/
static char *SafeMalloc( size_t size ){
  char *p;

  p = (char*)malloc(size);
  if( p==0 ){
    strcpy(zReplyStatus, "998");
    MakeLogEntry(1,100);  /* LOG: Malloc() failed */
    exit(1);
  }
  return p;
}

/* Forward reference */
static void BlockIPAddress(void);
static void ServiceUnavailable(int lineno);

/*
** Set the value of environment variable zVar to zValue.
*/
static void SetEnv(const char *zVar, const char *zValue){
  char *z;
  size_t len;
  if( zValue==0 ) zValue="";
  /* Disable an attempted bashdoor attack */
  if( strncmp(zValue,"() {",4)==0 ){
    BlockIPAddress();
    ServiceUnavailable(902); /* LOG: 902 bashdoor attack */
    zValue = "";
  }
  len = strlen(zVar) + strlen(zValue) + 2;
  z = SafeMalloc(len);
  sprintf(z,"%s=%s",zVar,zValue);
  putenv(z);
}

/*
** Remove the first space-delimited token from a string and return
** a pointer to it.  Add a NULL to the string to terminate the token.
** Make *zLeftOver point to the start of the next token.
*/
static char *GetFirstElement(char *zInput, char **zLeftOver){
  char *zResult = 0;
  if( zInput==0 ){
    if( zLeftOver ) *zLeftOver = 0;
    return 0;
  }
  while( isspace(*(unsigned char*)zInput) ){ zInput++; }
  zResult = zInput;
  while( *zInput && !isspace(*(unsigned char*)zInput) ){ zInput++; }
  if( *zInput ){
    *zInput = 0;
    zInput++;
    while( isspace(*(unsigned char*)zInput) ){ zInput++; }
  }
  if( zLeftOver ){ *zLeftOver = zInput; }
  return zResult;
}

/*
** Make a copy of a string into memory obtained from malloc.
*/
static char *StrDup(const char *zSrc){
  char *zDest;
  size_t size;

  if( zSrc==0 ) return 0;
  size = strlen(zSrc) + 1;
  zDest = (char*)SafeMalloc( size );
  strcpy(zDest,zSrc);
  return zDest;
}
static char *StrAppend(char *zPrior, const char *zSep, const char *zSrc){
  char *zDest;
  size_t size;
  size_t n0, n1, n2;

  if( zSrc==0 ) return 0;
  if( zPrior==0 ) return StrDup(zSrc);
  n0 = strlen(zPrior);
  n1 = strlen(zSep);
  n2 = strlen(zSrc);
  size = n0+n1+n2+1;
  zDest = (char*)SafeMalloc( size );
  memcpy(zDest, zPrior, n0);
  free(zPrior);
  memcpy(&zDest[n0],zSep,n1);
  memcpy(&zDest[n0+n1],zSrc,n2+1);
  return zDest;
}

/*
** Construct the REQUEST_URI value from zString and zQueryString.
**
** REQUEST_URI is nominally the second field of the first line of the
** HTTP request.  But we might have done some sanitization on the
** SCRIPT_NAME and/or PATH_INFO and we want to capture that in the
** REQUEST_URI.  Hence, the REQUEST_URI is recomputed before being
** sent to CGI or SCGI.
*/
static void ComputeRequestUri(void){
  if( zQueryString==0 || zQueryString[0]==0 ){
    zRequestUri = zScript;
  }else{
    zRequestUri = StrAppend(zScript, "?", zQueryString);
  }
}

/*
** Compare two ETag values. Return 0 if they match and non-zero if they differ.
**
** The one on the left might be a NULL pointer and it might be quoted.
*/
static int CompareEtags(const char *zA, const char *zB){
  if( zA==0 ) return 1;
  if( zA[0]=='"' ){
    int lenB = (int)strlen(zB);
    if( strncmp(zA+1, zB, lenB)==0 && zA[lenB+1]=='"' ) return 0;
  }
  return strcmp(zA, zB);
}

/*
** Break a line at the first \n or \r character seen.
*/
static void RemoveNewline(char *z){
  if( z==0 ) return;
  while( *z && *z!='\n' && *z!='\r' ){ z++; }
  *z = 0;
}

/* Render seconds since 1970 as an RFC822 date string.  Return
** a pointer to that string in a static buffer.
*/
static char *Rfc822Date(time_t t){
  struct tm *tm;
  static char zDate[100];
  tm = gmtime(&t);
  strftime(zDate, sizeof(zDate), "%a, %d %b %Y %H:%M:%S GMT", tm);
  return zDate;
}

/*
** Print a date tag in the header.  The name of the tag is zTag.
** The date is determined from the unix timestamp given.
*/
static int DateTag(const char *zTag, time_t t){
  return althttpd_printf("%s: %s\r\n", zTag, Rfc822Date(t));
}

/*
** Parse an RFC822-formatted timestamp as we'd expect from HTTP and return
** a Unix epoch time. <= zero is returned on failure.
*/
time_t ParseRfc822Date(const char *zDate){
  int mday, mon, year, yday, hour, min, sec;
  char zIgnore[4];
  char zMonth[4];
  static const char *const azMonths[] =
    {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  if( 7==sscanf(zDate, "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d", zIgnore,
                       &mday, zMonth, &year, &hour, &min, &sec)){
    if( year > 1900 ) year -= 1900;
    for(mon=0; mon<12; mon++){
      if( !strncmp( azMonths[mon], zMonth, 3 )){
        int nDay;
        int isLeapYr;
        static int priorDays[] =
         {  0, 31, 59, 90,120,151,181,212,243,273,304,334 };
        isLeapYr = year%4==0 && (year%100!=0 || (year+300)%400==0);
        yday = priorDays[mon] + mday - 1;
        if( isLeapYr && mon>1 ) yday++;
        nDay = (year-70)*365 + (year-69)/4 - year/100 + (year+300)/400 + yday;
        return ((time_t)(nDay*24 + hour)*60 + min)*60 + sec;
      }
    }
  }
  return 0;
}

/*
** Test procedure for ParseRfc822Date
*/
void TestParseRfc822Date(void){
  time_t t1, t2;
  for(t1=0; t1<0x7fffffff; t1 += 127){
    t2 = ParseRfc822Date(Rfc822Date(t1));
    assert( t1==t2 );
  }
}

/*
** Print the first line of a response followed by the server type.
*/
static void StartResponse(const char *zResultCode){
  time_t now;
  time(&now);
  if( statusSent ) return;
  nOut += althttpd_printf("%s %s\r\n",
                          zProtocol ? zProtocol : "HTTP/1.1",
                          zResultCode);
  strncpy(zReplyStatus, zResultCode, 3);
  zReplyStatus[3] = 0;
  if( zReplyStatus[0]>='4' ){
    closeConnection = 1;
  }
  if( closeConnection ){
    nOut += althttpd_printf("Connection: close\r\n");
  }else{
    nOut += althttpd_printf("Connection: keep-alive\r\n");
  }
  nOut += DateTag("Date", now);
  statusSent = 1;
}

/*
** Check all of the files in the zIPShunDir directory.  Unlink any
** files in that directory that have expired.
**
** This routine might be slow if there are a lot of blocker files.
** So it only runs when we are not in a hurry, such as prior to sending
** a 404 Not Found reply.
*/
static void UnlinkExpiredIPBlockers(void){
  DIR *pDir;
  struct dirent *pFile;
  size_t nIPShunDir;
  time_t now;
  char zFilename[2000];

  if( zIPShunDir==0 ) return;
  if( zIPShunDir[0]!='/' ) return;
  nIPShunDir = strlen(zIPShunDir);
  while( nIPShunDir>0 && zIPShunDir[nIPShunDir-1]=='/' ) nIPShunDir--;
  if( nIPShunDir > sizeof(zFilename)-100 ) return;
  memcpy(zFilename, zIPShunDir, nIPShunDir);
  zFilename[nIPShunDir] = 0;
  pDir = opendir(zFilename);
  if( pDir==0 ) return;
  zFilename[nIPShunDir] = '/';
  time(&now);
  while( (pFile = readdir(pDir))!=0 ){
    size_t nFile = strlen(pFile->d_name);
    int rc;
    struct stat statbuf;
    if( nIPShunDir+nFile >= sizeof(zFilename)-2 ) continue;
    if( strstr(pFile->d_name, "..") ) continue;
    memcpy(zFilename+nIPShunDir+1, pFile->d_name, nFile+1);
    memset(&statbuf, 0, sizeof(statbuf));
    rc = stat(zFilename, &statbuf);
    if( rc ) continue;
    if( !S_ISREG(statbuf.st_mode) ) continue;
    if( statbuf.st_size==0 ) continue;
    if( statbuf.st_size*5*BANISH_TIME + statbuf.st_mtime > now ) continue;
    unlink(zFilename);
  }
  closedir(pDir);
}

/* Return true if the request URI contained in zScript[] seems like a
** hack attempt.
*/
static int LikelyHackAttempt(void){
  if( zScript==0 ) return 0;
  if( zScript[0]==0 ) return 0;
  if( zScript[0]!='/' ) return 1;
  if( strstr(zScript, "/../")!=0 ) return 1;
  if( strstr(zScript, "/./")!=0 ) return 1;
  if( strstr(zScript, "_SELECT_")!=0 ) return 1;
  if( strstr(zScript, "_select_")!=0 ) return 1;
  if( strstr(zScript, "_sleep_")!=0 ) return 1;
  if( strstr(zScript, "_OR_")!=0 ) return 1;
  if( strstr(zScript, "_AND_")!=0 ) return 1;
  if( strstr(zScript, "/etc/passwd")!=0 ) return 1;
  if( strstr(zScript, "/bin/sh")!=0 ) return 1;
  if( strstr(zScript, "/.git/")!=0 ) return 1;
  return 0;
}

/*
** An abusive HTTP request has been submitted by the IP address zRemoteAddr.
** Block future requests coming from this IP address.
**
** This only happens if the zIPShunDir variable is set, which is only set
** by the --ipshun command-line option.  Without that setting, this routine
** is a no-op.
**
** If zIPShunDir is a valid directory, then this routine uses zRemoteAddr
** as the name of a file within that directory.  Cases:
**
** +  The file already exists and is not an empty file.  This will be the
**    case if the same IP was recently blocked, but the block has expired,
**    and yet the expiration was not so long ago that the blocking file has
**    been unlinked.  In this case, add one character to the file, which
**    will update its mtime (causing it to be active again) and increase
**    its expiration timeout.
**
** +  The file exists and is empty.  This happens if the administrator
**    uses "touch" to create the file.  An empty blocking file indicates
**    a permanent block.  Do nothing.
**
** +  The file does not exist.  Create it anew and make it one byte in size.
**
** The UnlinkExpiredIPBlockers() routine will run from time to time to
** unlink expired blocker files.  If the DisallowedRemoteAddr() routine finds
** an expired blocker file corresponding to zRemoteAddr, it might unlink
** that one blocker file if the file has been expired for long enough.
*/
static void BlockIPAddress(void){
  size_t nIPShunDir;
  size_t nRemoteAddr;
  int rc;
  struct stat statbuf;
  char zFullname[1000];

  if( zIPShunDir==0 ) return;
  if( zRemoteAddr==0 ) return;
  if( zRemoteAddr[0]==0 ) return;

  /* If we reach this point, it means that a suspicious request was
  ** received and we want to activate IP blocking on the remote
  ** address.
  */
  nIPShunDir = strlen(zIPShunDir);
  while( nIPShunDir>0 && zIPShunDir[nIPShunDir-1]=='/' ) nIPShunDir--;
  nRemoteAddr = strlen(zRemoteAddr);
  if( nIPShunDir + nRemoteAddr + 2 >= sizeof(zFullname) ){
    Malfunction(914, /* LOG: buffer overflow */
       "buffer overflow");
  }
  memcpy(zFullname, zIPShunDir, nIPShunDir);
  zFullname[nIPShunDir] = '/';
  memcpy(zFullname+nIPShunDir+1, zRemoteAddr, nRemoteAddr+1);
  rc = stat(zFullname, &statbuf);
  if( rc!=0 || statbuf.st_size>0 ){
    FILE *lock = fopen(zFullname, "a");
    if( lock ){
      fputc('X', lock);
      fclose(lock);
    }
  }
}

/*
** Send a service-unavailable reply.
*/
static void ServiceUnavailable(int lineno){
  StartResponse("503 Service Unavailable");
  nOut += althttpd_printf(
    "Content-type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Service to IP address %s temporarily blocked due to abuse\n",
    zRemoteAddr
  );
  closeConnection = 1;
  MakeLogEntry(0, lineno);
  althttpd_exit();
}

/*
** Tell the client that there is no such document
*/
static void NotFound(int lineno){
  UnlinkExpiredIPBlockers();
  if( LikelyHackAttempt() ){
    BlockIPAddress();
    ServiceUnavailable(lineno);
  }
  StartResponse("404 Not Found");
  nOut += althttpd_printf(
    "Content-type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<head><title lineno=\"%d\">Not Found</title></head>\n"
    "<body><h1>Document Not Found</h1>\n"
    "The document %s is not available on this server\n"
    "</body>\n", lineno, zScript);
  MakeLogEntry(0, lineno);
  althttpd_exit();
}

/*
** Tell the client that they are not welcomed here.
*/
static void Forbidden(int lineno){
  StartResponse("403 Forbidden");
  nOut += althttpd_printf(
    "Content-type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Access denied\n"
  );
  closeConnection = 1;
  MakeLogEntry(0, lineno);
  althttpd_exit();
}

/*
** Tell the client that authorization is required to access the
** document.
*/
static void NotAuthorized(const char *zRealm){
  StartResponse("401 Authorization Required");
  nOut += althttpd_printf(
    "WWW-Authenticate: Basic realm=\"%s\"\r\n"
    "Content-type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<head><title>Not Authorized</title></head>\n"
    "<body><h1>401 Not Authorized</h1>\n"
    "A login and password are required for this document\n"
    "</body>\n", zRealm);
  MakeLogEntry(0, 110);  /* LOG: Not authorized */
}

/*
** Tell the client that there is an error in the script.
*/
static void CgiError(void){
  StartResponse("500 Error");
  nOut += althttpd_printf(
    "Content-type: text/html; charset=utf-8\r\n"
    "\r\n"
    "<head><title>CGI Program Error</title></head>\n"
    "<body><h1>CGI Program Error</h1>\n"
    "The CGI program %s generated an error\n"
    "</body>\n", zScript);
  MakeLogEntry(0, 120);  /* LOG: CGI Error */
  althttpd_exit();
  exit(0);
}

/*
** Set the timeout in seconds.  0 means no-timeout.
*/
static void SetTimeout(int nSec, int lineNum){
  if( useTimeout ){
    nTimeoutLine = lineNum;
    alarm(nSec);
  }
}

/*
** This is called if we timeout or catch some other kind of signal.
** Log an error code which is 900+iSig and then quit.
*/
static void Timeout(int iSig){
  if( !debugFlag ){
    if( zScript && zScript[0] ){
      char zBuf[10];
      zBuf[0] = '9';
      zBuf[1] = '0' + (iSig/10)%10;
      zBuf[2] = '0' + iSig%10;
      zBuf[3] = 0;
      strcpy(zReplyStatus, zBuf);
      switch( iSig ){
        case SIGALRM:
          MakeLogEntry(0, nTimeoutLine);
          break;
        case SIGSEGV:
          MakeLogEntry(0, 131);  /* LOG: SIGSEGV */
          break;
        case SIGPIPE:
          MakeLogEntry(0, 132);  /* LOG: SIGPIPE */
          break;
        case SIGXCPU:
          MakeLogEntry(0, 133);  /* LOG: SIGXCPU */
          break;
        default:
          MakeLogEntry(0, 139);  /* LOG: Unknown signal */
          break;
      }
    }
    exit(0);
  }
}

/*
** Tell the client that there is an error in the script.
*/
static void CgiScriptWritable(void){
  StartResponse("500 CGI Configuration Error");
  nOut += althttpd_printf(
    "Content-type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "The CGI program %s is writable by users other than its owner.\n",
    zRealScript);
  MakeLogEntry(0, 140);  /* LOG: CGI script is writable */
  althttpd_exit();
}

/*
** Tell the client that the server malfunctioned.
*/
void Malfunction(int linenum, const char *zFormat, ...){
  va_list ap;
  va_start(ap, zFormat);
  StartResponse("500 Server Malfunction");
  nOut += althttpd_printf(
    "Content-type: text/plain; charset=utf-8\r\n"
    "\r\n"
    "Web server malfunctioned; error number %d\n\n", linenum);
  if( zFormat ){
    nOut += althttpd_vprintf(zFormat, ap);
    althttpd_printf("\n");
    nOut++;
  }
  va_end(ap);
  MakeLogEntry(0, linenum);
  althttpd_exit();
}

/*
** Do a server redirect to the document specified.  The document
** name not contain scheme or network location or the query string.
** It will be just the path.
*/
static void Redirect(const char *zPath, int iStatus, int finish, int lineno){
  switch( iStatus ){
    case 301:
      StartResponse("301 Permanent Redirect");
      break;
    case 308:
      StartResponse("308 Permanent Redirect");
      break;
    default:
      StartResponse("302 Temporary Redirect");
      break;
  }
  if( zServerPort==0 || zServerPort[0]==0 || strcmp(zServerPort,"80")==0 ){
    nOut += althttpd_printf("Location: %s://%s%s%s\r\n",
                   zHttpScheme, zServerName, zPath, zQuerySuffix);
  }else{
    nOut += althttpd_printf("Location: %s://%s:%s%s%s\r\n",
                   zHttpScheme, zServerName, zServerPort, zPath, zQuerySuffix);
  }
  if( finish ){
    nOut += althttpd_printf("Content-length: 0\r\n");
    nOut += althttpd_printf("\r\n");
    MakeLogEntry(0, lineno);
  }
  fflush(stdout);
}

/*
** This function treats its input as a base-64 string and returns the
** decoded value of that string.  Characters of input that are not
** valid base-64 characters (such as spaces and newlines) are ignored.
*/
static void Decode64(char *z64){
  char *zData;
  int n64;
  int i, j;
  int a, b, c, d;
  static int isInit = 0;
  static int trans[128];
  static unsigned char zBase[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  if( !isInit ){
    for(i=0; i<128; i++){ trans[i] = 0; }
    for(i=0; zBase[i]; i++){ trans[zBase[i] & 0x7f] = i; }
    isInit = 1;
  }
  n64 = strlen(z64);
  while( n64>0 && z64[n64-1]=='=' ) n64--;
  zData = z64;
  for(i=j=0; i+3<n64; i+=4){
    a = trans[z64[i] & 0x7f];
    b = trans[z64[i+1] & 0x7f];
    c = trans[z64[i+2] & 0x7f];
    d = trans[z64[i+3] & 0x7f];
    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
    zData[j++] = ((b<<4) & 0xf0) | ((c>>2) & 0x0f);
    zData[j++] = ((c<<6) & 0xc0) | (d & 0x3f);
  }
  if( i+2<n64 ){
    a = trans[z64[i] & 0x7f];
    b = trans[z64[i+1] & 0x7f];
    c = trans[z64[i+2] & 0x7f];
    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
    zData[j++] = ((b<<4) & 0xf0) | ((c>>2) & 0x0f);
  }else if( i+1<n64 ){
    a = trans[z64[i] & 0x7f];
    b = trans[z64[i+1] & 0x7f];
    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
  }
  zData[j] = 0;
}

#ifdef ENABLE_TLS
/* This is a self-signed cert in the PEM format that can be used when
** no other certs are available.
**
** NB: Use of this self-signed cert is wildly insecure.  Use for testing
** purposes only.
*/
static const char sslSelfCert[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIIDMTCCAhkCFGrDmuJkkzWERP/ITBvzwwI2lv0TMA0GCSqGSIb3DQEBCwUAMFQx\n"
"CzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOQzESMBAGA1UEBwwJQ2hhcmxvdHRlMRMw\n"
"EQYDVQQKDApGb3NzaWwtU0NNMQ8wDQYDVQQDDAZGb3NzaWwwIBcNMjExMjI3MTEz\n"
"MTU2WhgPMjEyMTEyMjcxMTMxNTZaMFQxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJO\n"
"QzESMBAGA1UEBwwJQ2hhcmxvdHRlMRMwEQYDVQQKDApGb3NzaWwtU0NNMQ8wDQYD\n"
"VQQDDAZGb3NzaWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCCbTU2\n"
"6GRQHQqLq7vyZ0OxpAxmgfAKCxt6eIz+jBi2ZM/CB5vVXWVh2+SkSiWEA3UZiUqX\n"
"xZlzmS/CglZdiwLLDJML8B4OiV72oivFH/vJ7+cbvh1dTxnYiHuww7GfQngPrLfe\n"
"fiIYPDk1GTUJHBQ7Ue477F7F8vKuHdVgwktF/JDM6M60aSqlo2D/oysirrb+dlur\n"
"Tlv0rjsYOfq6bLAajoL3qi/vek6DNssoywbge4PfbTgS9g7Gcgncbcet5pvaS12J\n"
"avhFcd4JU4Ity49Hl9S/C2MfZ1tE53xVggRwKz4FPj65M5uymTdcxtjKXtCxIE1k\n"
"KxJxXQh7rIYjm+RTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFkdtpqcybAzJN8G\n"
"+ONuUm5sXNbWta7JGvm8l0BTSBcCUtJA3hn16iJqXA9KmLnaF2denC4EYk+KlVU1\n"
"QXxskPJ4jB8A5B05jMijYv0nzCxKhviI8CR7GLEEGKzeg9pbW0+O3vaVehoZtdFX\n"
"z3SsCssr9QjCLiApQxMzW1Iv3od2JXeHBwfVMFrWA1VCEUCRs8OSW/VOqDPJLVEi\n"
"G6wxc4kN9dLK+5S29q3nzl24/qzXoF8P9Re5KBCbrwaHgy+OEEceq5jkmfGFxXjw\n"
"pvVCNry5uAhH5NqbXZampUWqiWtM4eTaIPo7Y2mDA1uWhuWtO6F9PsnFJlQHCnwy\n"
"s/TsrXk=\n"
"-----END CERTIFICATE-----\n";

/* This is the private-key corresponding to the cert above
*/
static const char sslSelfPKey[] = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCCbTU26GRQHQqL\n"
"q7vyZ0OxpAxmgfAKCxt6eIz+jBi2ZM/CB5vVXWVh2+SkSiWEA3UZiUqXxZlzmS/C\n"
"glZdiwLLDJML8B4OiV72oivFH/vJ7+cbvh1dTxnYiHuww7GfQngPrLfefiIYPDk1\n"
"GTUJHBQ7Ue477F7F8vKuHdVgwktF/JDM6M60aSqlo2D/oysirrb+dlurTlv0rjsY\n"
"Ofq6bLAajoL3qi/vek6DNssoywbge4PfbTgS9g7Gcgncbcet5pvaS12JavhFcd4J\n"
"U4Ity49Hl9S/C2MfZ1tE53xVggRwKz4FPj65M5uymTdcxtjKXtCxIE1kKxJxXQh7\n"
"rIYjm+RTAgMBAAECggEANfTH1vc8yIe7HRzmm9lsf8jF+II4s2705y2H5qY+cvYx\n"
"nKtZJGOG1X0KkYy7CGoFv5K0cSUl3lS5FVamM/yWIzoIex/Sz2C1EIL2aI5as6ez\n"
"jB6SN0/J+XI8+Vt7186/rHxfdIPpxuzjHbxX3HTpScETNWcLrghbrPxakbTPPxwt\n"
"+x7QlPmmkFNuMfvkzToFf9NdwL++44TeBPOpvD/Lrw+eyqdth9RJPq9cM96plh9V\n"
"HuRqeD8+QNafaXBdSQs3FJK/cDK/vWGKZWIfFVSDbDhwYljkXGijreFjtXQfkkpF\n"
"rl1J87/H9Ee7z8fTD2YXQHl+0/rghAVtac3u54dpQQKBgQC2XG3OEeMrOp9dNkUd\n"
"F8VffUg0ecwG+9L3LCe7U71K0kPmXjV6xNnuYcNQu84kptc5vI8wD23p29LaxdNc\n"
"9m0lcw06/YYBOPkNphcHkINYZTvVJF10mL3isymzMaTtwDkZUkOjL1B+MTiFT/qp\n"
"ARKrTYGJ4HxY7+tUkI5pUmg4PQKBgQC3GA4d1Rz3Pb/RRpcsZgWknKsKhoN36mSn\n"
"xFJ3wPBvVv2B1ltTMzh/+the0ty6clzMrvoLERzRcheDsNrc/j/TUVG8sVdBYJwX\n"
"tMZyFW4NVMOErT/1ukh6jBqIMBo6NJL3EV/AKj0yniksgKOr0/AAduAccnGST8Jd\n"
"SHOdjwvHzwKBgGZBq/zqgNTDuYseHGE07CMgcDWkumiMGv8ozlq3mSR0hUiPOTPP\n"
"YFjQjyIdPXnF6FfiyPPtIvgIoNK2LVAqiod+XUPf152l4dnqcW13dn9BvOxGyPTR\n"
"lWCikFaAFviOWjY9r9m4dU1dslDmySqthFd0TZgPvgps9ivkJ0cdw30NAoGAMC/E\n"
"h1VvKiK2OP27C5ROJ+STn1GHiCfIFd81VQ8SODtMvL8NifgRBp2eFFaqgOdYRQZI\n"
"CGGYlAbS6XXCJCdF5Peh62dA75PdgN+y2pOJQzjrvB9cle9Q4++7i9wdCvSLOTr5\n"
"WDnFoWy+qVexu6crovOmR9ZWzYrwPFy1EOJ010ECgYBl7Q+jmjOSqsVwhFZ0U7LG\n"
"diN+vXhWfn1wfOWd8u79oaqU/Oy7xyKW2p3H5z2KFrBM/vib53Lh4EwFZjcX+jVG\n"
"krAmbL+M/hP7z3TD2UbESAzR/c6l7FU45xN84Lsz5npkR8H/uAHuqLgb9e430Mjx\n"
"YNMwdb8rChHHChNZu6zuxw==\n"
"-----END PRIVATE KEY-----\n";

/*
** Read a PEM certificate from memory and push it into an SSL_CTX.
** Return the number of errors.
*/
static int sslctx_use_cert_from_mem(
  SSL_CTX *ctx,
  const char *pData,
  int nData
){
  BIO *in;
  int rc = 1;
  X509 *x = 0;
  X509 *cert = 0;

  in = BIO_new_mem_buf(pData, nData);
  if( in==0 ) goto end_of_ucfm;
  x = X509_new();
  if( x==0 ) goto end_of_ucfm;
  cert = PEM_read_bio_X509(in, &x, 0, 0);
  if( cert==0 ) goto end_of_ucfm;
  rc = SSL_CTX_use_certificate(ctx, x)<=0;
end_of_ucfm:
  X509_free(x);
  BIO_free(in);
  return rc;
}

/*
** Read a PEM private key from memory and add it to an SSL_CTX.
** Return the number of errors.
*/
static int sslctx_use_pkey_from_mem(
  SSL_CTX *ctx,
  const char *pData,
  int nData
){
  int rc = 1;
  BIO *in;
  EVP_PKEY *pkey = 0;

  in = BIO_new_mem_buf(pData, nData);
  if( in==0 ) goto end_of_upkfm;
  pkey = PEM_read_bio_PrivateKey(in, 0, 0, 0);
  if( pkey==0 ) goto end_of_upkfm;
  rc = SSL_CTX_use_PrivateKey(ctx, pkey)<=0;
  EVP_PKEY_free(pkey);
end_of_upkfm:
  BIO_free(in);
  return rc;
}

/*
** Initialize the SSL library so that it is able to handle
** server-side connections.  Invokes Malfunction() if there are
** any problems (so does not return on error).
**
** If zKeyFile and zCertFile are not NULL, then they are the names
** of disk files that hold the certificate and private-key for the
** server.  If zCertFile is not NULL but zKeyFile is NULL, then
** zCertFile is assumed to be a concatenation of the certificate and
** the private-key in the PEM format.
**
** If zCertFile is "unsafe-builtin" then a built-in self-signed cert
** is used and zKeyFile is ignored.
**
** Error messages may contain the paths to the given files, but this
** function is called before the server starts listening for requests,
** so those will never be sent to clients.
*/
static void ssl_init_server(const char *zCertFile,
                            const char *zKeyFile){
  if( tlsState.isInit==0 ){
    const int useSelfSigned = zCertFile
      && 0==strcmp("unsafe-builtin", zCertFile);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    tlsState.ctx = SSL_CTX_new(SSLv23_server_method());
    if( tlsState.ctx==0 ){
      ERR_print_errors_fp(stderr);
      Malfunction(501,   /* LOG: Error initializing the SSL Server */
           "Error initializing the SSL server");
    }
    if( !useSelfSigned && zCertFile && zCertFile[0] ){
      if( SSL_CTX_use_certificate_chain_file(tlsState.ctx,
                                             zCertFile)!=1 ){
        ERR_print_errors_fp(stderr);
        Malfunction(502,  /* LOG: Error loading CERT file */
           "Error loading CERT file \"%s\"", zCertFile);
      }
      if( zKeyFile==0 ) zKeyFile = zCertFile;
      if( SSL_CTX_use_PrivateKey_file(tlsState.ctx, zKeyFile,
                                      SSL_FILETYPE_PEM)<=0 ){
        ERR_print_errors_fp(stderr);
        Malfunction(503,  /* LOG: Error loading private key file */
            "Error loading PRIVATE KEY from file \"%s\"",
            zKeyFile);
      }
    }else if( useSelfSigned ){
      if(sslctx_use_cert_from_mem(tlsState.ctx, sslSelfCert, -1)
         || sslctx_use_pkey_from_mem(tlsState.ctx, sslSelfPKey, -1) ){
        Malfunction(504,  /* LOG: Error loading self-signed cert */
           "Error loading self-signed CERT");
      }
    }else{
      Malfunction(505,"No certificate TLS specified"); /* LOG: No cert */
    }
    if( !SSL_CTX_check_private_key(tlsState.ctx) ){
      Malfunction(506,  /* LOG: private key does not match cert */
           "PRIVATE KEY \"%s\" does not match CERT \"%s\"",
           zKeyFile, zCertFile);
    }
    SSL_CTX_set_mode(tlsState.ctx, SSL_MODE_AUTO_RETRY);
    tlsState.isInit = 2;
  }else{
    assert( tlsState.isInit==2 );
  }
}
#endif /*ENABLE_TLS*/

/*
** Check to see if basic authorization credentials are provided for
** the user according to the information in zAuthFile.  Return true
** if authorized.  Return false if not authorized.
**
** File format:
**
**    *  Blank lines and lines that begin with '#' are ignored
**    *  "http-redirect" forces a redirect to HTTPS if not there already
**    *  "https-only" disallows operation in HTTP
**    *  "user NAME LOGIN:PASSWORD" checks to see if LOGIN:PASSWORD 
**       authorization credentials are provided, and if so sets the
**       REMOTE_USER to NAME.
**    *  "realm TEXT" sets the realm to TEXT.
**    *  "anyone" bypasses authentication and allows anyone to see the
**       files.  Useful in combination with "http-redirect"
*/
static int CheckBasicAuthorization(const char *zAuthFile){
  FILE *in;
  char *zRealm = "unknown realm";
  char *zLoginPswd;
  char *zName;
  char zLine[2000];

  in = fopen(zAuthFile, "rb");
  if( in==0 ){
    NotFound(150);  /* LOG: Cannot open -auth file */
    return 0;
  }
  if( zAuthArg ) Decode64(zAuthArg);
  while( fgets(zLine, sizeof(zLine), in) ){
    char *zFieldName;
    char *zVal;

    zFieldName = GetFirstElement(zLine,&zVal);
    if( zFieldName==0 || *zFieldName==0 ) continue;
    if( zFieldName[0]=='#' ) continue;
    RemoveNewline(zVal);
    if( strcmp(zFieldName, "realm")==0 ){
      zRealm = StrDup(zVal);
    }else if( strcmp(zFieldName,"user")==0 ){
      if( zAuthArg==0 ) continue;
      zName = GetFirstElement(zVal, &zVal);
      zLoginPswd = GetFirstElement(zVal, &zVal);
      if( zLoginPswd==0 ) continue;
      if( zAuthArg && strcmp(zAuthArg,zLoginPswd)==0 ){
        zRemoteUser = StrDup(zName);
        fclose(in);
        return 1;
      }
    }else if( strcmp(zFieldName,"https-only")==0 ){
      if( !useHttps ){
        NotFound(160);  /* LOG:  http request on https-only page */
        fclose(in);
        return 0;
      }
    }else if( strcmp(zFieldName,"http-redirect")==0 ){
      if( !useHttps ){
        zHttpScheme = "https";
        Redirect(zScript, 301, 1, 170); /* LOG: -auth redirect */
        fclose(in);
        return 0;
      }
    }else if( strcmp(zFieldName,"anyone")==0 ){
      fclose(in);
      return 1;
    }else{
      NotFound(180);  /* LOG:  malformed entry in -auth file */
      fclose(in);
      return 0;
    }
  }
  fclose(in);
  NotAuthorized(zRealm);
  return 0;
}

/*
** Type for mapping file extensions to mimetypes and type-specific
** internal flags.
*/
typedef struct MimeTypeDef {
  const char *zSuffix;       /* The file suffix */
  unsigned char size;        /* Length of the suffix */
  unsigned char flags;       /* See the MTF_xxx flags macros */
  const char *zMimetype;     /* The corresponding mimetype */
} MimeTypeDef;


/* Flags for mimetype flags. These MUST match the values hard-coded in
** GetMimeType(). That function avoids the macros for space reasons. */
#define MTF_NOCGI      0x1   /* Never treat as CGI */
#define MTF_NOCHARSET  0x2   /* Elide charset=... from Content-Type */

/*
** Guess the mime-type of a document based on its name.
*/
const MimeTypeDef *GetMimeType(const char *zName, int nName){
  const char *z;
  int i;
  int first, last;
  int len;
  char zSuffix[20];

  /* A table of mimetypes based on file suffixes. 
  ** Suffixes must be in sorted order so that we can do a binary
  ** search to find the mime-type
  */
  static const MimeTypeDef aMime[] = {
  { "ai",         2, 0x00, "application/postscript"           },
  { "aif",        3, 0x00, "audio/x-aiff"                     },
  { "aifc",       4, 0x00, "audio/x-aiff"                     },
  { "aiff",       4, 0x00, "audio/x-aiff"                     },
  { "arj",        3, 0x00, "application/x-arj-compressed"     },
  { "asc",        3, 0x00, "text/plain"                       },
  { "asf",        3, 0x00, "video/x-ms-asf"                   },
  { "asx",        3, 0x00, "video/x-ms-asx"                   },
  { "au",         2, 0x00, "audio/ulaw"                       },
  { "avi",        3, 0x00, "video/x-msvideo"                  },
  { "bat",        3, 0x00, "application/x-msdos-program"      },
  { "bcpio",      5, 0x00, "application/x-bcpio"              },
  { "bin",        3, 0x00, "application/octet-stream"         },
  { "c",          1, 0x00, "text/plain"                       },
  { "cc",         2, 0x00, "text/plain"                       },
  { "ccad",       4, 0x00, "application/clariscad"            },
  { "cdf",        3, 0x00, "application/x-netcdf"             },
  { "class",      5, 0x00, "application/octet-stream"         },
  { "cod",        3, 0x00, "application/vnd.rim.cod"          },
  { "com",        3, 0x00, "application/x-msdos-program"      },
  { "cpio",       4, 0x00, "application/x-cpio"               },
  { "cpt",        3, 0x00, "application/mac-compactpro"       },
  { "csh",        3, 0x00, "application/x-csh"                },
  { "css",        3, 0x00, "text/css"                         },
  { "dcr",        3, 0x00, "application/x-director"           },
  { "deb",        3, 0x00, "application/x-debian-package"     },
  { "dir",        3, 0x00, "application/x-director"           },
  { "dl",         2, 0x00, "video/dl"                         },
  { "dms",        3, 0x00, "application/octet-stream"         },
  { "doc",        3, 0x00, "application/msword"               },
  { "drw",        3, 0x00, "application/drafting"             },
  { "dvi",        3, 0x00, "application/x-dvi"                },
  { "dwg",        3, 0x00, "application/acad"                 },
  { "dxf",        3, 0x00, "application/dxf"                  },
  { "dxr",        3, 0x00, "application/x-director"           },
  { "eps",        3, 0x00, "application/postscript"           },
  { "etx",        3, 0x00, "text/x-setext"                    },
  { "exe",        3, 0x00, "application/octet-stream"         },
  { "ez",         2, 0x00, "application/andrew-inset"         },
  { "f",          1, 0x00, "text/plain"                       },
  { "f90",        3, 0x00, "text/plain"                       },
  { "fli",        3, 0x00, "video/fli"                        },
  { "flv",        3, 0x00, "video/flv"                        },
  { "gif",        3, 0x00, "image/gif"                        },
  { "gl",         2, 0x00, "video/gl"                         },
  { "gtar",       4, 0x00, "application/x-gtar"               },
  { "gz",         2, 0x00, "application/x-gzip"               },
  { "hdf",        3, 0x00, "application/x-hdf"                },
  { "hh",         2, 0x00, "text/plain"                       },
  { "hqx",        3, 0x00, "application/mac-binhex40"         },
  { "h",          1, 0x00, "text/plain"                       },
  { "htm",        3, 0x00, "text/html"                        },
  { "html",       4, 0x00, "text/html"                        },
  { "ice",        3, 0x00, "x-conference/x-cooltalk"          },
  { "ief",        3, 0x00, "image/ief"                        },
  { "iges",       4, 0x00, "model/iges"                       },
  { "igs",        3, 0x00, "model/iges"                       },
  { "ips",        3, 0x00, "application/x-ipscript"           },
  { "ipx",        3, 0x00, "application/x-ipix"               },
  { "jad",        3, 0x00, "text/vnd.sun.j2me.app-descriptor" },
  { "jar",        3, 0x00, "application/java-archive"         },
  { "jpeg",       4, 0x00, "image/jpeg"                       },
  { "jpe",        3, 0x00, "image/jpeg"                       },
  { "jpg",        3, 0x00, "image/jpeg"                       },
  { "js",         2, 0x00, "text/x-javascript"                },
  /* application/javascript is commonly used for JS, but the
  ** HTML spec says text/javascript is correct:
  ** https://html.spec.whatwg.org/multipage/scripting.html
  ** #scriptingLanguages:javascript-mime-type */
  { "json",       4, 0x00, "application/json"                 },
  { "kar",        3, 0x00, "audio/midi"                       },
  { "latex",      5, 0x00, "application/x-latex"              },
  { "lha",        3, 0x00, "application/octet-stream"         },
  { "lsp",        3, 0x00, "application/x-lisp"               },
  { "lzh",        3, 0x00, "application/octet-stream"         },
  { "m",          1, 0x00, "text/plain"                       },
  { "m3u",        3, 0x00, "audio/x-mpegurl"                  },
  { "man",        3, 0x00, "application/x-troff-man"          },
  { "me",         2, 0x00, "application/x-troff-me"           },
  { "mesh",       4, 0x00, "model/mesh"                       },
  { "mid",        3, 0x00, "audio/midi"                       },
  { "midi",       4, 0x00, "audio/midi"                       },
  { "mif",        3, 0x00, "application/x-mif"                },
  { "mime",       4, 0x00, "www/mime"                         },
  { "mjs",        3, 0x00, "text/javascript" /*EM6 modules*/  },
  { "movie",      5, 0x00, "video/x-sgi-movie"                },
  { "mov",        3, 0x00, "video/quicktime"                  },
  { "mp2",        3, 0x00, "audio/mpeg"                       },
  { "mp2",        3, 0x00, "video/mpeg"                       },
  { "mp3",        3, 0x00, "audio/mpeg"                       },
  { "mpeg",       4, 0x00, "video/mpeg"                       },
  { "mpe",        3, 0x00, "video/mpeg"                       },
  { "mpga",       4, 0x00, "audio/mpeg"                       },
  { "mpg",        3, 0x00, "video/mpeg"                       },
  { "ms",         2, 0x00, "application/x-troff-ms"           },
  { "msh",        3, 0x00, "model/mesh"                       },
  { "nc",         2, 0x00, "application/x-netcdf"             },
  { "oda",        3, 0x00, "application/oda"                  },
  { "ogg",        3, 0x00, "application/ogg"                  },
  { "ogm",        3, 0x00, "application/ogg"                  },
  { "pbm",        3, 0x00, "image/x-portable-bitmap"          },
  { "pdb",        3, 0x00, "chemical/x-pdb"                   },
  { "pdf",        3, 0x00, "application/pdf"                  },
  { "pgm",        3, 0x00, "image/x-portable-graymap"         },
  { "pgn",        3, 0x00, "application/x-chess-pgn"          },
  { "pgp",        3, 0x00, "application/pgp"                  },
  { "pl",         2, 0x00, "application/x-perl"               },
  { "pm",         2, 0x00, "application/x-perl"               },
  { "png",        3, 0x00, "image/png"                        },
  { "pnm",        3, 0x00, "image/x-portable-anymap"          },
  { "pot",        3, 0x00, "application/mspowerpoint"         },
  { "ppm",        3, 0x00, "image/x-portable-pixmap"          },
  { "pps",        3, 0x00, "application/mspowerpoint"         },
  { "ppt",        3, 0x00, "application/mspowerpoint"         },
  { "ppz",        3, 0x00, "application/mspowerpoint"         },
  { "pre",        3, 0x00, "application/x-freelance"          },
  { "prt",        3, 0x00, "application/pro_eng"              },
  { "ps",         2, 0x00, "application/postscript"           },
  { "qt",         2, 0x00, "video/quicktime"                  },
  { "ra",         2, 0x00, "audio/x-realaudio"                },
  { "ram",        3, 0x00, "audio/x-pn-realaudio"             },
  { "rar",        3, 0x00, "application/x-rar-compressed"     },
  { "ras",        3, 0x00, "image/cmu-raster"                 },
  { "ras",        3, 0x00, "image/x-cmu-raster"               },
  { "rgb",        3, 0x00, "image/x-rgb"                      },
  { "rm",         2, 0x00, "audio/x-pn-realaudio"             },
  { "roff",       4, 0x00, "application/x-troff"              },
  { "rpm",        3, 0x00, "audio/x-pn-realaudio-plugin"      },
  { "rtf",        3, 0x00, "application/rtf"                  },
  { "rtf",        3, 0x00, "text/rtf"                         },
  { "rtx",        3, 0x00, "text/richtext"                    },
  { "scm",        3, 0x00, "application/x-lotusscreencam"     },
  { "set",        3, 0x00, "application/set"                  },
  { "sgml",       4, 0x00, "text/sgml"                        },
  { "sgm",        3, 0x00, "text/sgml"                        },
  { "sh",         2, 0x00, "application/x-sh"                 },
  { "shar",       4, 0x00, "application/x-shar"               },
  { "silo",       4, 0x00, "model/mesh"                       },
  { "sit",        3, 0x00, "application/x-stuffit"            },
  { "skd",        3, 0x00, "application/x-koan"               },
  { "skm",        3, 0x00, "application/x-koan"               },
  { "skp",        3, 0x00, "application/x-koan"               },
  { "skt",        3, 0x00, "application/x-koan"               },
  { "smi",        3, 0x00, "application/smil"                 },
  { "smil",       4, 0x00, "application/smil"                 },
  { "snd",        3, 0x00, "audio/basic"                      },
  { "sol",        3, 0x00, "application/solids"               },
  { "spl",        3, 0x00, "application/x-futuresplash"       },
  { "src",        3, 0x00, "application/x-wais-source"        },
  { "step",       4, 0x00, "application/STEP"                 },
  { "stl",        3, 0x00, "application/SLA"                  },
  { "stp",        3, 0x00, "application/STEP"                 },
  { "sv4cpio",    7, 0x00, "application/x-sv4cpio"            },
  { "sv4crc",     6, 0x00, "application/x-sv4crc"             },
  { "svg",        3, 0x00, "image/svg+xml"                    },
  { "swf",        3, 0x00, "application/x-shockwave-flash"    },
  { "t",          1, 0x00, "application/x-troff"              },
  { "tar",        3, 0x00, "application/x-tar"                },
  { "tcl",        3, 0x00, "application/x-tcl"                },
  { "tex",        3, 0x00, "application/x-tex"                },
  { "texi",       4, 0x00, "application/x-texinfo"            },
  { "texinfo",    7, 0x00, "application/x-texinfo"            },
  { "tgz",        3, 0x00, "application/x-tar-gz"             },
  { "tiff",       4, 0x00, "image/tiff"                       },
  { "tif",        3, 0x00, "image/tiff"                       },
  { "tr",         2, 0x00, "application/x-troff"              },
  { "tsi",        3, 0x00, "audio/TSP-audio"                  },
  { "tsp",        3, 0x00, "application/dsptype"              },
  { "tsv",        3, 0x00, "text/tab-separated-values"        },
  { "txt",        3, 0x00, "text/plain"                       },
  { "unv",        3, 0x00, "application/i-deas"               },
  { "ustar",      5, 0x00, "application/x-ustar"              },
  { "vcd",        3, 0x00, "application/x-cdlink"             },
  { "vda",        3, 0x00, "application/vda"                  },
  { "viv",        3, 0x00, "video/vnd.vivo"                   },
  { "vivo",       4, 0x00, "video/vnd.vivo"                   },
  { "vrml",       4, 0x00, "model/vrml"                       },
  { "vsix",       4, 0x00, "application/vsix"                 },
  { "wasm",       4, 0x03, "application/wasm"                 },
  { "wav",        3, 0x00, "audio/x-wav"                      },
  { "wax",        3, 0x00, "audio/x-ms-wax"                   },
  { "wiki",       4, 0x00, "application/x-fossil-wiki"        },
  { "wma",        3, 0x00, "audio/x-ms-wma"                   },
  { "wmv",        3, 0x00, "video/x-ms-wmv"                   },
  { "wmx",        3, 0x00, "video/x-ms-wmx"                   },
  { "wrl",        3, 0x00, "model/vrml"                       },
  { "wvx",        3, 0x00, "video/x-ms-wvx"                   },
  { "xbm",        3, 0x00, "image/x-xbitmap"                  },
  { "xlc",        3, 0x00, "application/vnd.ms-excel"         },
  { "xll",        3, 0x00, "application/vnd.ms-excel"         },
  { "xlm",        3, 0x00, "application/vnd.ms-excel"         },
  { "xls",        3, 0x00, "application/vnd.ms-excel"         },
  { "xlw",        3, 0x00, "application/vnd.ms-excel"         },
  { "xml",        3, 0x00, "text/xml"                         },
  { "xpm",        3, 0x00, "image/x-xpixmap"                  },
  { "xwd",        3, 0x00, "image/x-xwindowdump"              },
  { "xyz",        3, 0x00, "chemical/x-pdb"                   },
  { "zip",        3, 0x00, "application/zip"                  },
  };

  for(i=nName-1; i>0 && zName[i]!='.'; i--){}
  z = &zName[i+1];
  len = nName - i;
  if( len<(int)sizeof(zSuffix)-1 ){
    strcpy(zSuffix, z);
    for(i=0; zSuffix[i]; i++) zSuffix[i] = tolower(zSuffix[i]);
    first = 0;
    last = sizeof(aMime)/sizeof(aMime[0]);
    while( first<=last ){
      int c;
      i = (first+last)/2;
      c = strcmp(zSuffix, aMime[i].zSuffix);
      if( c==0 ) return &aMime[i];
      if( c<0 ){
        last = i-1;
      }else{
        first = i+1;
      }
    }
  }
  return 0;
}

/*
** The following table contains 1 for all characters that are permitted in
** the part of the URL before the query parameters and fragment.
**
** Allowed characters:  0-9a-zA-Z,-./:_~
**
** Disallowed characters include:  !"#$%&'()*+;<=>?@[\]^`{|}
*/
static const char allowedInName[] = {
      /*  x0  x1  x2  x3  x4  x5  x6  x7  x8  x9  xa  xb  xc  xd  xe  xf */
/* 0x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 1x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 2x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  1,  1,
/* 3x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,
/* 4x */   0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
/* 5x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  1,
/* 6x */   0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
/* 7x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  1,  0,
/* 8x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* 9x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Ax */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Bx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Cx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Dx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Ex */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
/* Fx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};

/*
** Remove all disallowed characters in the input string z[].  Convert any
** disallowed characters into "_".
**
** Not that the three character sequence "%XX" where X is any byte is
** converted into a single "_" character.
**
** Return the number of characters converted.  An "%XX" -> "_" conversion
** counts as a single character.
*/
static int sanitizeString(char *z){
  int nChange = 0;
  while( *z ){
    if( !allowedInName[*(unsigned char*)z] ){
      char cNew = '_';
      if( *z=='%' && z[1]!=0 && z[2]!=0 ){
        int i;
        if( z[1]=='2' ){
          if( z[2]=='e' || z[2]=='E' ) cNew = '.';
          if( z[2]=='f' || z[2]=='F' ) cNew = '/';
        }
        for(i=3; (z[i-2] = z[i])!=0; i++){}
      }
      *z = cNew;
      nChange++;
    }
    z++;
  }
  return nChange;
}

/*
** Count the number of "/" characters in a string.
*/
static int countSlashes(const char *z){
  int n = 0;
  while( *z ) if( *(z++)=='/' ) n++;
  return n;
}

#ifdef ENABLE_TLS
/*
** Create a new server-side codec.  The argument is the socket's file
** descriptor from which the codec reads and writes. The returned
** memory must eventually be passed to tls_close_server().
*/
static void *tls_new_server(int iSocket){
  TlsServerConn *pServer = malloc(sizeof(*pServer));
  BIO *b = pServer ? BIO_new_socket(iSocket, 0) : NULL;
  if( NULL==b ){
    Malfunction(507,"Cannot allocate TlsServerConn."); /* LOG: TlsServerConn */
  }
  assert(NULL!=tlsState.ctx);
  pServer->ssl = SSL_new(tlsState.ctx);
  pServer->bio = b;
  pServer->iSocket = iSocket;
  SSL_set_bio(pServer->ssl, b, b);
  SSL_accept(pServer->ssl);
  return (void*)pServer;
}

/*
** Close a server-side code previously returned from tls_new_server().
*/
static void tls_close_server(void *pServerArg){
  TlsServerConn *pServer = (TlsServerConn*)pServerArg;
  SSL_free(pServer->ssl);
  memset(pServer, 0, sizeof(TlsServerConn));
  free(pServer);
}

static void tls_atexit(void){
  if( tlsState.sslCon ){
    tls_close_server(tlsState.sslCon);
    tlsState.sslCon = NULL;
  }
}
#endif /* ENABLE_TLS */


/*
** Works like fgets():
**
** Read a single line of input into s[].  Ensure that s[] is zero-terminated.
** The s[] buffer is size bytes and so at most size-1 bytes will be read.
**
** Return a pointer to s[] on success, or NULL at end-of-input.
**
** If in TLS mode, the final argument is ignored and the TLS
** connection is read instead.
*/
static char *althttpd_fgets(char *s, int size, FILE *in){
  if( useHttps!=2 ){
    return fgets(s, size, in);
  }
#ifdef ENABLE_TLS
  assert(NULL!=tlsState.sslCon);
  return tls_gets(tlsState.sslCon, s, size);
#else
  Malfunction(508,"SSL not available"); /* LOG: SSL not available */
  return NULL;
#endif
}
/*
** Works like fread() but may, depending on connection state, use
** libssl to read the data (in which case the final argument is
** ignored). The target buffer must be at least (sz*nmemb) bytes.
*/
static size_t althttpd_fread(void *tgt, size_t sz, size_t nmemb, FILE *in){
  if( useHttps!=2 ){
    return fread(tgt, sz, nmemb, in);
  }
#ifdef ENABLE_TLS
  assert(NULL!=tlsState.sslCon);
  return tls_read_server(tlsState.sslCon, tgt, sz*nmemb);
#else
  Malfunction(509,"SSL not available"); /* LOG: SSL not available */
  return 0;
#endif
}

/*
** Works like fwrite() but may, depending on connection state, write to
** the active TLS connection (in which case the final argument is
** ignored).
** 
*/
static size_t althttpd_fwrite(
  void const *src,          /* Buffer containing content to write */
  size_t sz,                /* Size of each element in the buffer */
  size_t nmemb,             /* Number of elements to write */
  FILE *out                 /* Write on this stream */
){
  if( useHttps!=2 ){
    return fwrite(src, sz, nmemb, out);
  }
#ifdef ENABLE_TLS
  assert(NULL!=tlsState.sslCon);
  return tls_write_server(tlsState.sslCon, src, sz*nmemb);
#else
  Malfunction(510,"SSL not available"); /* LOG: SSL not available */
  return 0;
#endif
}

/*
** In non-builtin-TLS mode, fflush()es the given FILE handle, else
** this is a no-op.
*/
static void althttpd_fflush(FILE *f){
  if( useHttps!=2 ){
    fflush(f);
  }
}

/*
** Transfer nXfer bytes from in to out, after first discarding
** nSkip bytes from in.  Increment the nOut global variable
** according to the number of bytes transferred.
**
** When running in built-in TLS mode the 2nd argument is ignored and
** output is instead sent via the TLS connection.
*/
static void xferBytes(FILE *in, FILE *out, int nXfer, int nSkip){
  size_t n;
  size_t got;
  char zBuf[16384];
  while( nSkip>0 ){
    n = nSkip;
    if( n>sizeof(zBuf) ) n = sizeof(zBuf);
    got = fread(zBuf, 1, n, in);
    if( got==0 ) break;
    nSkip -= got;
  }
  while( nXfer>0 ){
    n = nXfer;
    if( n>sizeof(zBuf) ) n = sizeof(zBuf);
    got = fread(zBuf, 1, n, in);
    if( got==0 ) break;
    althttpd_fwrite(zBuf, got, 1, out);
    nOut += got;
    nXfer -= got;
  }
}

/*
** Send the text of the file named by zFile as the reply.  Use the
** suffix on the end of the zFile name to determine the mimetype.
**
** Return 1 to omit making a log entry for the reply.
*/
static int SendFile(
  const char *zFile,      /* Name of the file to send */
  int lenFile,            /* Length of the zFile name in bytes */
  struct stat *pStat      /* Result of a stat() against zFile */
){
  const char *zContentType;
  time_t t;
  FILE *in;
  size_t szFilename;
  char zETag[100];
  const MimeTypeDef *pMimeType;
  int bAddCharset = 1;
  const char *zEncoding = 0;
  struct stat statbuf;
  char zGzFilename[2000];

  pMimeType = GetMimeType(zFile, lenFile);
  zContentType = pMimeType
    ? pMimeType->zMimetype : "application/octet-stream";
  if( pMimeType && (MTF_NOCHARSET & pMimeType->flags) ){
    bAddCharset = 0;
  }
  if( zPostData ){ free(zPostData); zPostData = 0; }
  sprintf(zETag, "m%xs%x", (int)pStat->st_mtime, (int)pStat->st_size);
  if( CompareEtags(zIfNoneMatch,zETag)==0
   || (zIfModifiedSince!=0
        && (t = ParseRfc822Date(zIfModifiedSince))>0
        && t>=pStat->st_mtime)
  ){
    StartResponse("304 Not Modified");
    nOut += DateTag("Last-Modified", pStat->st_mtime);
    nOut += althttpd_printf("Cache-Control: max-age=%d\r\n", mxAge);
    nOut += althttpd_printf("ETag: \"%s\"\r\n", zETag);
    nOut += althttpd_printf("\r\n");
    fflush(stdout);
    MakeLogEntry(0, 470);  /* LOG: ETag Cache Hit */
    return 1;
  }
  if( rangeEnd<=0
   && zAcceptEncoding
   && strstr(zAcceptEncoding,"gzip")!=0
  ){
    szFilename = strlen(zFile);
    if( szFilename < sizeof(zGzFilename)-10 ){
      memcpy(zGzFilename, zFile, szFilename);
      memcpy(zGzFilename + szFilename, ".gz", 4);
      if( access(zGzFilename, R_OK)==0 ){
        memset(&statbuf, 0, sizeof(statbuf));
        if( stat(zGzFilename, &statbuf)==0 ){
          zEncoding = "gzip";
          zFile = zGzFilename;
          pStat = &statbuf;
        }      
      }
    }
  }
  in = fopen(zFile,"rb");
  if( in==0 ) NotFound(480); /* LOG: fopen() failed for static content */
  if( rangeEnd>0 && rangeStart<pStat->st_size ){
    StartResponse("206 Partial Content");
    if( rangeEnd>=pStat->st_size ){
      rangeEnd = pStat->st_size-1;
    }
    nOut += althttpd_printf("Content-Range: bytes %d-%d/%d\r\n",
                    rangeStart, rangeEnd, (int)pStat->st_size);
    pStat->st_size = rangeEnd + 1 - rangeStart;
  }else{
    StartResponse("200 OK");
    rangeStart = 0;
  }
  nOut += DateTag("Last-Modified", pStat->st_mtime);
  nOut += althttpd_printf("Cache-Control: max-age=%d\r\n", mxAge);
  nOut += althttpd_printf("ETag: \"%s\"\r\n", zETag);
  nOut += althttpd_printf("Content-type: %s%s\r\n",zContentType,
                          bAddCharset ? "; charset=utf-8" : "");
  if( zEncoding ){
    nOut += althttpd_printf("Content-encoding: %s\r\n", zEncoding);
  }
  nOut += althttpd_printf("Content-length: %d\r\n\r\n",(int)pStat->st_size);
  fflush(stdout);
  if( strcmp(zMethod,"HEAD")==0 ){
    MakeLogEntry(0, 2); /* LOG: Normal HEAD reply */
    fclose(in);
    fflush(stdout);
    return 1;
  }
#ifdef linux
  if( 2!=useHttps ){
    off_t offset = rangeStart;
    nOut += sendfile(fileno(stdout), fileno(in), &offset, pStat->st_size);
  }else
#endif
  {
    xferBytes(in, stdout, (int)pStat->st_size, rangeStart);
  }
  fclose(in);
  return 0;
}

/*
** Streams all contents from in to out. If in TLS mode, the
** output stream is ignored and the output instead goes
** to the TLS channel.
*/
static void stream_file(FILE * const in, FILE * const out){
  enum { STREAMBUF_SIZE = 1024 * 4 };
  char streamBuf[STREAMBUF_SIZE];
  size_t n;
  while( (n = fread(streamBuf, 1,sizeof(STREAMBUF_SIZE),in)) ){
    althttpd_fwrite(streamBuf, 1, n, out);
  }
}

/*
** A CGI or SCGI script has run and is sending its reply back across
** the channel "in".  Process this reply into an appropriate HTTP reply.
** Close the "in" channel when done.
**
** If isNPH is true, the input is assumed to be from a
** non-parsed-header CGI and is passed on as-is to stdout or the TLS
** layer, depending on the connection state.
*/
static void CgiHandleReply(FILE *in, int isNPH){
  int seenContentLength = 0;   /* True if Content-length: header seen */
  int contentLength = 0;       /* The content length */
  size_t nRes = 0;             /* Bytes of payload */
  size_t nMalloc = 0;          /* Bytes of space allocated to aRes */
  char *aRes = 0;              /* Payload */
  int c;                       /* Next character from in */
  char *z;                     /* Pointer to something inside of zLine */
  int iStatus = 0;             /* Reply status code */
  char zLine[1000];            /* One line of reply from the CGI script */

  /* Set a 1-hour timeout, so that we can implement Hanging-GET or
  ** long-poll style CGIs.  The RLIMIT_CPU will serve as a safety
  ** to help prevent a run-away CGI */
  SetTimeout(60*60, 800); /* LOG: CGI Handler timeout */

  if( isNPH ){
    /*
    ** Non-parsed-header output: simply pipe it out as-is. We
    ** need to go through this routine, instead of simply exec()'ing,
    ** in order to go through the TLS output channel.
    */
    stream_file(in, stdout);
    fclose(in);
    return;
  }

  while( fgets(zLine,sizeof(zLine),in) && !isspace((unsigned char)zLine[0]) ){
    if( strncasecmp(zLine,"Location:",9)==0 ){
      StartResponse("302 Redirect");
      RemoveNewline(zLine);
      z = &zLine[10];
      while( isspace(*(unsigned char*)z) ){ z++; }
      nOut += althttpd_printf("Location: %s\r\n",z);
      rangeEnd = 0;
    }else if( strncasecmp(zLine,"Status:",7)==0 ){
      int i;
      for(i=7; isspace((unsigned char)zLine[i]); i++){}
      nOut += althttpd_printf("%s %s", zProtocol, &zLine[i]);
      strncpy(zReplyStatus, &zLine[i], 3);
      zReplyStatus[3] = 0;
      iStatus = atoi(zReplyStatus);
      if( iStatus!=200 ) rangeEnd = 0;
      statusSent = 1;
    }else if( strncasecmp(zLine, "Content-length:", 15)==0 ){
      seenContentLength = 1;
      contentLength = atoi(zLine+15);
    }else{
      size_t nLine = strlen(zLine);
      if( nRes+nLine >= nMalloc ){
        nMalloc += nMalloc + nLine*2;
        aRes = realloc(aRes, nMalloc+1);
        if( aRes==0 ){
          Malfunction(600, "Out of memory: %d bytes", nMalloc); /* LOG: OOM */
        }
      }
      memcpy(aRes+nRes, zLine, nLine);
      nRes += nLine;
    }
  }
  /* Copy everything else thru without change or analysis.
  */
  if( rangeEnd>0 && seenContentLength && rangeStart<contentLength ){
    StartResponse("206 Partial Content");
    if( rangeEnd>=contentLength ){
      rangeEnd = contentLength-1;
    }
    nOut += althttpd_printf("Content-Range: bytes %d-%d/%d\r\n",
                            rangeStart, rangeEnd, contentLength);
    contentLength = rangeEnd + 1 - rangeStart;
  }else{
    StartResponse("200 OK");
  }
  if( nRes>0 ){
    aRes[nRes] = 0;
    althttpd_fwrite(aRes, nRes, 1, stdout);
    nOut += nRes;
    nRes = 0;
  }
  if( iStatus==304 ){
    nOut += althttpd_printf("\r\n\r\n");
  }else if( seenContentLength ){
    nOut += althttpd_printf("Content-length: %d\r\n\r\n", contentLength);
    xferBytes(in, stdout, contentLength, rangeStart);
  }else{
    while( (c = getc(in))!=EOF ){
      if( nRes>=nMalloc ){
        nMalloc = nMalloc*2 + 1000;
        aRes = realloc(aRes, nMalloc+1);
        if( aRes==0 ){
           Malfunction(610, "Out of memory: %d bytes", nMalloc); /* LOG: OOM */
        }
      }
      aRes[nRes++] = c;
    }
    if( nRes ){
      aRes[nRes] = 0;
      nOut += althttpd_printf("Content-length: %d\r\n\r\n", (int)nRes);
      nOut += althttpd_fwrite(aRes, nRes, 1, stdout);
    }else{
      nOut += althttpd_printf("Content-length: 0\r\n\r\n");
    }
  }
  free(aRes);
  fclose(in);
}

/*
** Send an SCGI request to a host identified by zFile and process the
** reply.
*/
static void SendScgiRequest(const char *zFile, const char *zScript){
  FILE *in;
  FILE *s;
  char *z;
  char *zHost;
  char *zPort = 0;
  char *zRelight = 0;
  char *zFallback = 0;
  int rc;
  int iSocket = -1;
  struct addrinfo hints;
  struct addrinfo *ai = 0;
  struct addrinfo *p;
  char *zHdr;
  size_t nHdr = 0;
  size_t nHdrAlloc;
  int i;
  char zLine[1000];
  char zExtra[1000];
  in = fopen(zFile, "rb");
  if( in==0 ){
    Malfunction(700, "cannot open \"%s\"\n", zFile); /* LOG: cannot open file */
  }
  if( fgets(zLine, sizeof(zLine)-1, in)==0 ){
    Malfunction(701, "cannot read \"%s\"\n", zFile); /* LOG: cannot read file */
  }
  if( strncmp(zLine,"SCGI ",5)!=0 ){
    Malfunction(702, /* LOG: bad SCGI spec */
       "misformatted SCGI spec \"%s\"\n", zFile);
  }
  z = zLine+5;
  zHost = GetFirstElement(z,&z);
  zPort = GetFirstElement(z,0);
  if( zHost==0 || zHost[0]==0 || zPort==0 || zPort[0]==0 ){
    Malfunction(703, /* LOG: bad SCGI spec (2) */
       "misformatted SCGI spec \"%s\"\n", zFile);
  }
  while( fgets(zExtra, sizeof(zExtra)-1, in) ){
    char *zCmd = GetFirstElement(zExtra,&z);
    if( zCmd==0 ) continue;
    if( zCmd[0]=='#' ) continue;
    RemoveNewline(z);
    if( strcmp(zCmd, "relight:")==0 ){
      free(zRelight);
      zRelight = StrDup(z);
      continue;
    }
    if( strcmp(zCmd, "fallback:")==0 ){
      free(zFallback);
      zFallback = StrDup(z);
      continue;
    }
    Malfunction(704, /* LOG: Unrecognized line in SCGI spec */
       "unrecognized line in SCGI spec: \"%s %s\"\n",
                zCmd, z ? z : "");
  }
  fclose(in);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  rc = getaddrinfo(zHost,zPort,&hints,&ai);
  if( rc ){
    Malfunction(705, /* LOG: Cannot resolve SCGI server name */
       "cannot resolve SCGI server name %s:%s\n%s\n",
                zHost, zPort, gai_strerror(rc));
  }
  while(1){  /* Exit via break */
    for(p=ai; p; p=p->ai_next){
      iSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if( iSocket<0 ) continue;
      if( connect(iSocket,p->ai_addr,p->ai_addrlen)>=0 ) break;
      close(iSocket);
    }
    if( iSocket<0 || (s = fdopen(iSocket,"r+"))==0 ){
      if( iSocket>=0 ) close(iSocket);
      if( zRelight ){
        rc = system(zRelight);
        if( rc ){
          Malfunction(721, /* LOG: SCGI relight failed */
             "Relight failed with %d: \"%s\"\n",
                      rc, zRelight);
        }
        free(zRelight);
        zRelight = 0;
        sleep(1);
        continue;
      }
      if( zFallback ){
        struct stat statbuf;
        int rc;
        memset(&statbuf, 0, sizeof(statbuf));
        if( chdir(zDir) ){
          char zBuf[1000];
          Malfunction(720, /* LOG: chdir() failed */
               "cannot chdir to [%s] from [%s]", 
               zDir, getcwd(zBuf,999));
        }
        rc = stat(zFallback, &statbuf);
        if( rc==0 && S_ISREG(statbuf.st_mode) && access(zFallback,R_OK)==0 ){
          closeConnection = 1;
          rc = SendFile(zFallback, (int)strlen(zFallback), &statbuf);
          free(zFallback);
          althttpd_exit();
        }else{
          Malfunction(706, /* LOG: bad SCGI fallback */
             "bad fallback file: \"%s\"\n", zFallback);
        }
      }
      Malfunction(707, /* LOG: Cannot open socket to SCGI */
           "cannot open socket to SCGI server %s\n",
                  zScript);
    }
    break;
  }

  nHdrAlloc = 0;
  zHdr = 0;
  if( zContentLength==0 ) zContentLength = "0";
  ComputeRequestUri();
  zScgi = "1";
  for(i=0; i<(int)(sizeof(cgienv)/sizeof(cgienv[0])); i++){
    int n1, n2;
    if( cgienv[i].pzEnvValue[0]==0 ) continue;
    n1 = (int)strlen(cgienv[i].zEnvName);
    n2 = (int)strlen(*cgienv[i].pzEnvValue);
    if( n1+n2+2+nHdr >= nHdrAlloc ){
      nHdrAlloc = nHdr + n1 + n2 + 1000;
      zHdr = realloc(zHdr, nHdrAlloc);
      if( zHdr==0 ){
        Malfunction(708, "out of memory"); /* LOG: OOM */
      }
    }
    memcpy(zHdr+nHdr, cgienv[i].zEnvName, n1);
    nHdr += n1;
    zHdr[nHdr++] = 0;
    memcpy(zHdr+nHdr, *cgienv[i].pzEnvValue, n2);
    nHdr += n2;
    zHdr[nHdr++] = 0;
  }
  zScgi = 0;
  fprintf(s,"%d:",(int)nHdr);
  fwrite(zHdr, 1, nHdr, s);
  fprintf(s,",");
  free(zHdr);
  if( nPostData>0 ){
    size_t wrote = 0;
    while( wrote<(size_t)nPostData ){
      size_t n = fwrite(zPostData+wrote, 1, nPostData-wrote, s);
      if( n<=0 ) break;
      wrote += n;
    }
    free(zPostData);
    zPostData = 0;
    nPostData = 0;
  }
  fflush(s);
  CgiHandleReply(s, 0);
}

/*
** If running in builtin TLS mode, initializes the SSL I/O
** state and returns 1, else does nothing and returns 0.
*/
static int tls_init_conn(int iSocket){
#ifdef ENABLE_TLS
  if( 2==useHttps ){
    /*assert(NULL==tlsState.sslCon);*/
    if( NULL==tlsState.sslCon ){
      tlsState.sslCon = (TlsServerConn *)tls_new_server(iSocket);
      if( NULL==tlsState.sslCon ){
        Malfunction(512, /* LOG: TLS context */
          "Could not instantiate TLS context.");
      }
      atexit(tls_atexit);
    }
    return 1;
  }
#else
  if( 0==iSocket ){/*unused arg*/}
#endif
  return 0;
}
static void tls_close_conn(void){
#ifdef ENABLE_TLS
  if( tlsState.sslCon ){
    tls_close_server(tlsState.sslCon);
    tlsState.sslCon = NULL;
  }
#endif
}

/*
** Check to see if zRemoteAddr is disallowed.  Return true if it is
** disallowed and false if not.
**
** zRemoteAddr is disallowed if:
**
**    *  The zIPShunDir variable is not NULL
**
**    *  zIPShunDir is the name of a directory
**
**    *  There is a file in zIPShunDir whose name is exactly zRemoteAddr
**       and that is N bytes in size.
**
**    *  N==0 or the mtime of the file is less than N*BANISH_TIME seconds
**       ago.
**
** If N>0 and the mtime is greater than N*5*BANISH_TIME seconds 
** (25 minutes per byte, by default) old, then the file is deleted.
**
** The size of the file determines how long the embargo is suppose to
** last.  A zero-byte file embargos forever.  Otherwise, the embargo
** is for BANISH_TIME bytes for each byte in the file.
*/
static int DisallowedRemoteAddr(void){
  char zFullname[1000];
  size_t nIPShunDir;
  size_t nRemoteAddr;
  int rc;
  struct stat statbuf;
  time_t now;

  if( zIPShunDir==0 ) return 0;
  if( zRemoteAddr==0 ) return 0;
  if( zIPShunDir[0]!='/' ){
    Malfunction(910, /* LOG: argument to --ipshun should be absolute path */
       "The --ipshun directory should have an absolute path");
  }
  nIPShunDir = strlen(zIPShunDir);
  while( nIPShunDir>0 && zIPShunDir[nIPShunDir-1]=='/' ) nIPShunDir--;
  nRemoteAddr = strlen(zRemoteAddr);
  if( nIPShunDir + nRemoteAddr + 2 >= sizeof(zFullname) ){
    Malfunction(912, /* LOG: RemoteAddr filename too big */
       "RemoteAddr filename too big");
  }
  if( zRemoteAddr[0]==0
   || zRemoteAddr[0]=='.'
   || strchr(zRemoteAddr,'/')!=0
  ){
    Malfunction(913, /* LOG: RemoteAddr contains suspicious characters */
       "RemoteAddr contains suspicious characters");
  }
  memcpy(zFullname, zIPShunDir, nIPShunDir);
  zFullname[nIPShunDir] = '/';
  memcpy(zFullname+nIPShunDir+1, zRemoteAddr, nRemoteAddr+1);
  memset(&statbuf, 0, sizeof(statbuf));
  rc = stat(zFullname, &statbuf);
  if( rc ) return 0;  /* No such file, hence no restrictions */
  if( statbuf.st_size==0 ) return 1;  /* Permanently banned */
  time(&now);
  if( statbuf.st_size*BANISH_TIME + statbuf.st_mtime >= now ){
    return 1;  /* Currently under a ban */
  }
  if( statbuf.st_size*5*BANISH_TIME + statbuf.st_mtime < now ){
    unlink(zFullname);
  }
  return 0;
}

/*
** This routine processes a single HTTP request on standard input and
** sends the reply to standard output.  If the argument is 1 it means
** that we are should close the socket without processing additional
** HTTP requests after the current request finishes.  0 means we are
** allowed to keep the connection open and to process additional requests.
** This routine may choose to close the connection even if the argument
** is 0.
** 
** If the connection should be closed, this routine calls exit() and
** thus never returns.  If this routine does return it means that another
** HTTP request may appear on the wire.
**
** socketId must be 0 (if running via xinetd/etc) or the socket ID
** accept()ed by http_server(). It is only used for built-in TLS
** mode.
*/
void ProcessOneRequest(int forceClose, int socketId){
  int i, j, j0;
  char *z;                  /* Used to parse up a string */
  struct stat statbuf;      /* Information about the file to be retrieved */
  FILE *in;                 /* For reading from CGI scripts */
#ifdef LOG_HEADER
  FILE *hdrLog = 0;         /* Log file for complete header content */
#endif
  char zLine[10000];        /* A buffer for input lines or forming names */
  const MimeTypeDef *pMimeType = 0; /* URI's mimetype */


  /* Must see a header within 10 seconds for the first request.
  ** Allow up to 5 more minutes for the follow-on requests
  */
  if( useTimeout ){
    if( nRequest>0 ){
      SetTimeout(60*5, 801);  /* LOG: Timeout request header (1+) */
    }else{
      SetTimeout(10, 802);    /* LOG: Timeout request header (0) */
    }
  }

  /* Change directories to the root of the HTTP filesystem
  */
  if( chdir(zRoot[0] ? zRoot : "/")!=0 ){
    char zBuf[1000];
    Malfunction(190,   /* LOG: chdir() failed */
         "cannot chdir to [%s] from [%s]",
         zRoot, getcwd(zBuf,sizeof(zBuf)-1));
  }
  nRequest++;
  tls_init_conn(socketId);

  /* Get the first line of the request and parse out the
  ** method, the script and the protocol.
  */
  omitLog = 1;
  if( althttpd_fgets(zLine,sizeof(zLine),stdin)==0 ){
    exit(0);
  }
  gettimeofday(&beginTime, 0);
  omitLog = 0;
  nIn += (i = (int)strlen(zLine));

  /* Parse the first line of the HTTP request */
  zMethod = StrDup(GetFirstElement(zLine,&z));
  zRealScript = zScript = StrDup(GetFirstElement(z,&z));
  zProtocol = StrDup(GetFirstElement(z,&z));
  if( zProtocol==0
   || strncmp(zProtocol,"HTTP/",5)!=0
   || strlen(zProtocol)!=8
   || i>9990
  ){
    zProtocol = 0;
    if( i<=9990 ){
      StartResponse("400 Bad Request");
      nOut += althttpd_printf(
        "Content-type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "This server does not understand the requested protocol\n"
      );
      MakeLogEntry(0, 200); /* LOG: bad protocol in HTTP header */
    }else{
      StartResponse("414 URI Too Long");
      nOut += althttpd_printf(
        "Content-type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "URI too long\n"
      );
      MakeLogEntry(0, 201); /* LOG: bad protocol in HTTP header */
    }
    althttpd_exit();
  }
  if( zScript[0]!='/' ) NotFound(210); /* LOG: Empty request URI */
  while( zScript[1]=='/' ){
    zScript++;
    zRealScript++;
  }
  if( forceClose ){
    closeConnection = 1;
  }else if( zProtocol[5]<'1' || zProtocol[7]<'1' ){
    closeConnection = 1;
  }

  /* This very simple server only understands the GET, POST
  ** and HEAD methods
  */
  if( strcmp(zMethod,"GET")!=0 && strcmp(zMethod,"POST")!=0
       && strcmp(zMethod,"HEAD")!=0 ){
    StartResponse("501 Not Implemented");
    nOut += althttpd_printf(
      "Content-type: text/plain; charset=utf-8\r\n"
      "\r\n"
      "The %s method is not implemented on this server.\n",
      zMethod);
    MakeLogEntry(0, 220); /* LOG: Unknown request method */
    althttpd_exit();
  }

  /* If there is a log file (if zLogFile!=0) and if the pathname in
  ** the first line of the http request contains the magic string
  ** "FullHeaderLog" then write the complete header text into the
  ** file %s(zLogFile)-hdr.  Overwrite the file.  This is for protocol
  ** debugging only and is only enabled if althttpd is compiled with
  ** the -DLOG_HEADER=1 option.
  */
#ifdef LOG_HEADER
  if( zLogFile
   && strstr(zScript,"FullHeaderLog")!=0
   && strlen(zLogFile)<sizeof(zLine)-50
  ){
    sprintf(zLine, "%s-hdr", zLogFile);
    hdrLog = fopen(zLine, "wb");
  }
#endif


  /* Get all the optional fields that follow the first line.
  */
  zCookie = 0;
  zAuthType = 0;
  zRemoteUser = 0;
  zReferer = 0;
  zIfNoneMatch = 0;
  zIfModifiedSince = 0;
  zContentLength = 0;
  rangeEnd = 0;
  while( althttpd_fgets(zLine,sizeof(zLine),stdin) ){
    char *zFieldName;
    char *zVal;

#ifdef LOG_HEADER
    if( hdrLog ) fprintf(hdrLog, "%s", zLine);
#endif
    nIn += strlen(zLine);
    zFieldName = GetFirstElement(zLine,&zVal);
    if( zFieldName==0 || *zFieldName==0 ) break;
    RemoveNewline(zVal);
    if( strcasecmp(zFieldName,"User-Agent:")==0 ){
      zAgent = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Accept:")==0 ){
      zAccept = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Accept-Encoding:")==0 ){
      zAcceptEncoding = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Content-length:")==0 ){
      zContentLength = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Content-type:")==0 ){
      zContentType = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Referer:")==0 ){
      zReferer = StrDup(zVal);
      if( strstr(zVal, "devids.net/")!=0 ){ zReferer = "devids.net.smut";
        Forbidden(230); /* LOG: Referrer is devids.net */
      }
    }else if( strcasecmp(zFieldName,"Cookie:")==0 ){
      zCookie = StrAppend(zCookie,"; ",zVal);
    }else if( strcasecmp(zFieldName,"Connection:")==0 ){
      if( strcasecmp(zVal,"close")==0 ){
        closeConnection = 1;
      }else if( !forceClose && strcasecmp(zVal, "keep-alive")==0 ){
        closeConnection = 0;
      }
    }else if( strcasecmp(zFieldName,"Host:")==0 ){
      int inSquare = 0;
      char c;
      if( sanitizeString(zVal) ){
        Forbidden(240);  /* LOG: Illegal content in HOST: parameter */
      }
      zHttpHost = StrDup(zVal);
      zServerPort = zServerName = StrDup(zHttpHost);
      while( zServerPort && (c = *zServerPort)!=0
              && (c!=':' || inSquare) ){
        if( c=='[' ) inSquare = 1;
        if( c==']' ) inSquare = 0;
        zServerPort++;
      }
      if( zServerPort && *zServerPort ){
        *zServerPort = 0;
        zServerPort++;
      }
      if( zRealPort ){
        zServerPort = StrDup(zRealPort);
      }
    }else if( strcasecmp(zFieldName,"Authorization:")==0 ){
      zAuthType = GetFirstElement(StrDup(zVal), &zAuthArg);
    }else if( strcasecmp(zFieldName,"If-None-Match:")==0 ){
      zIfNoneMatch = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"If-Modified-Since:")==0 ){
      zIfModifiedSince = StrDup(zVal);
    }else if( strcasecmp(zFieldName,"Range:")==0
           && strcmp(zMethod,"GET")==0 ){
      int x1 = 0, x2 = 0;
      int n = sscanf(zVal, "bytes=%d-%d", &x1, &x2);
      if( n==2 && x1>=0 && x2>=x1 ){
        rangeStart = x1;
        rangeEnd = x2;
      }else if( n==1 && x1>0 ){
        rangeStart = x1;
        rangeEnd = 0x7fffffff;
      }
    }
  }
#ifdef LOG_HEADER
  if( hdrLog ) fclose(hdrLog);
#endif

  /* Disallow requests from certain clients */
  if( zAgent ){
    const char *azDisallow[] = {
      "Windows 9",
      "Download Master",
      "Ezooms/",
      "HTTrace",
      "AhrefsBot",
      "MicroMessenger",
      "OPPO A33 Build",
      "SemrushBot",
      "MegaIndex.ru",
      "MJ12bot",
      "Chrome/0.A.B.C",
      "Neevabot/",
      "BLEXBot/",
      "Synapse",
    };
    size_t ii;
    for(ii=0; ii<sizeof(azDisallow)/sizeof(azDisallow[0]); ii++){
      if( strstr(zAgent,azDisallow[ii])!=0 ){
        Forbidden(250);  /* LOG: Disallowed user agent */
      }
    }
#if 0
    /* Spider attack from 2019-04-24 */
    if( strcmp(zAgent,
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36")==0 ){
      Forbidden(251);  /* LOG: Disallowed user agent (20190424) */
    }
#endif
  }
#if 0
  if( zReferer ){
    static const char *azDisallow[] = {
      "skidrowcrack.com",
      "hoshiyuugi.tistory.com",
      "skidrowgames.net",
    };
    int i;
    for(i=0; i<sizeof(azDisallow)/sizeof(azDisallow[0]); i++){
      if( strstr(zReferer, azDisallow[i])!=0 ){
        NotFound(260);  /* LOG: Disallowed referrer */
      }
    }
  }
#endif

  /* Make an extra effort to get a valid server name and port number.
  ** Only Netscape provides this information.  If the browser is
  ** Internet Explorer, then we have to find out the information for
  ** ourselves.
  */
  if( zServerName==0 ){
    zServerName = SafeMalloc( 100 );
    gethostname(zServerName,100);
  }
  if( zServerPort==0 || *zServerPort==0 ){
    zServerPort = DEFAULT_PORT;
  }

  /* Remove the query string from the end of the requested file.
  */
  for(z=zScript; *z && *z!='?'; z++){}
  if( *z=='?' ){
    zQuerySuffix = StrDup(z);
    *z = 0;
  }else{
    zQuerySuffix = "";
  }
  zQueryString = *zQuerySuffix ? &zQuerySuffix[1] : zQuerySuffix;

  /* Create either a memory buffer to hold the POST query data */
  if( zMethod[0]=='P' && zContentLength!=0 ){
    size_t len = atoi(zContentLength);
    if( len>MAX_CONTENT_LENGTH ){
      StartResponse("500 Request too large");
      nOut += althttpd_printf(
        "Content-type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Too much POST data\n"
      );
      MakeLogEntry(0, 270); /* LOG: Request too large */
      althttpd_exit();
    }
    rangeEnd = 0;
    zPostData = SafeMalloc( len+1 );
    SetTimeout(15 + len/2000, 803);  /* LOG: Timeout POST data */
    nPostData = althttpd_fread(zPostData,1,len,stdin);
    nIn += nPostData;
  }

  /* Make sure the running time is not too great */
  SetTimeout(30, 804);  /* LOG: Timeout decode HTTP request */

  /* Refuse to process the request if the IP address has been banished */
  if( zIPShunDir && DisallowedRemoteAddr() ){
    ServiceUnavailable(901); /* LOG: Prohibited remote IP address */
  }

  /* Convert all unusual characters in the script name into "_".
  **
  ** This is a defense against various attacks, XSS attacks in particular.
  */
  sanitizeString(zScript);

  /* Do not allow "/." or "/-" to to occur anywhere in the entity name.
  ** This prevents attacks involving ".." and also allows us to create
  ** files and directories whose names begin with "-" or "." which are
  ** invisible to the webserver.
  **
  ** Exception:  Allow the "/.well-known/" prefix in accordance with
  ** RFC-5785.
  */
  for(z=zScript; *z; z++){
    if( *z=='/' && (z[1]=='.' || z[1]=='-') ){
      if( strncmp(zScript,"/.well-known/",13)==0 && (z[1]!='.' || z[2]!='.') ){
        /* Exception:  Allow "/." and "/-" for URLs that being with
        ** "/.well-known/".  But do not allow "/..". */
        continue;
      }
      NotFound(300); /* LOG: Path element begins with "." or "-" */
    }
  }

  /* Figure out what the root of the filesystem should be.  If the
  ** HTTP_HOST parameter exists (stored in zHttpHost) then remove the
  ** port number from the end (if any), convert all characters to lower
  ** case, and convert non-alphanumber characters (including ".") to "_".
  ** Then try to find a directory with that name and the extension .website.
  ** If not found, look for "default.website".
  */
  if( zScript[0]!='/' ){
    NotFound(310); /* LOG: URI does not start with "/" */
  }
  if( strlen(zRoot)+40 >= sizeof(zLine) ){
    NotFound(320); /* LOG: URI too long */
  }
  if( zHttpHost==0 || zHttpHost[0]==0 ){
    NotFound(330);  /* LOG: Missing HOST: parameter */
  }else if( strlen(zHttpHost)+strlen(zRoot)+10 >= sizeof(zLine) ){
    NotFound(340);  /* LOG: HOST parameter too long */
  }else{
    sprintf(zLine, "%s/%s", zRoot, zHttpHost);
    for(i=strlen(zRoot)+1; zLine[i] && zLine[i]!=':'; i++){
      unsigned char c = (unsigned char)zLine[i];
      if( !isalnum(c) ){
        if( c=='.' && (zLine[i+1]==0 || zLine[i+1]==':') ){
          /* If the client sent a FQDN with a "." at the end
          ** (example: "sqlite.org." instead of just "sqlite.org") then
          ** omit the final "." from the document root directory name */
          break;
        }
        zLine[i] = '_';
      }else if( isupper(c) ){
        zLine[i] = tolower(c);
      }
    }
    strcpy(&zLine[i], ".website");
  }
  if( stat(zLine,&statbuf) || !S_ISDIR(statbuf.st_mode) ){
    sprintf(zLine, "%s/default.website", zRoot);
    if( stat(zLine,&statbuf) || !S_ISDIR(statbuf.st_mode) ){
      if( standalone ){
        sprintf(zLine, "%s", zRoot);
      }else{
        NotFound(350);  /* LOG: *.website permissions */
      }
    }
  }
  zHome = StrDup(zLine);
  /* Change directories to the root of the HTTP filesystem
  */
  if( chdir(zHome)!=0 ){
    char zBuf[1000];
    Malfunction(360,  /* LOG: chdir() failed */
         "cannot chdir to [%s] from [%s]",
         zHome, getcwd(zBuf,999));
  }

  /* Locate the file in the filesystem.  We might have to append
  ** a name like "/home" or "/index.html" or "/index.cgi" in order
  ** to find it.  Any excess path information is put into the
  ** zPathInfo variable.
  */
  j = j0 = (int)strlen(zLine);
  i = 0;
  while( zScript[i] ){
    while( zScript[i] && (i==0 || zScript[i]!='/') ){
      zLine[j] = zScript[i];
      i++; j++;
    }
    zLine[j] = 0;
    /* fprintf(stderr, "searching [%s]...\n", zLine); */
    if( stat(zLine,&statbuf)!=0 ){
      int stillSearching = 1;
      while( stillSearching && i>0 && j>j0 ){
        while( j>j0 && zLine[j-1]!='/' ){ j--; }
        strcpy(&zLine[j-1], "/not-found.html");
        if( stat(zLine,&statbuf)==0 && S_ISREG(statbuf.st_mode)
            && access(zLine,R_OK)==0 ){
          zRealScript = StrDup(&zLine[j0]);
          Redirect(zRealScript, 302, 1, 370); /* LOG: redirect to not-found */
          return;
        }else{
          j--;
        }
      }
      if( stillSearching ) NotFound(380); /* LOG: URI not found */
      break;
    }
    if( S_ISREG(statbuf.st_mode) ){
      if( access(zLine,R_OK) ){
        NotFound(390);  /* LOG: File not readable */
      }
      zRealScript = StrDup(&zLine[j0]);
      break;
    }
    if( zScript[i]==0 || zScript[i+1]==0 ){
      static const char *azIndex[] = {
        "/home", "/index", "/index.html", "/index.cgi"
      };
      int k = j>0 && zLine[j-1]=='/' ? j-1 : j;
      unsigned int jj;
      for(jj=0; jj<sizeof(azIndex)/sizeof(azIndex[0]); jj++){
        strcpy(&zLine[k],azIndex[jj]);
        if( stat(zLine,&statbuf)!=0 ) continue;
        if( !S_ISREG(statbuf.st_mode) ) continue;
        if( access(zLine,R_OK) ) continue;
        break;
      }
      if( jj>=sizeof(azIndex)/sizeof(azIndex[0]) ){
        NotFound(400); /* LOG: URI is a directory w/o index.html */
      }
      zRealScript = StrDup(&zLine[j0]);
      if( zScript[i]==0 ){
        /* If the requested URL does not end with "/" but we had to
        ** append "index.html", then a redirect is necessary.  Otherwise
        ** none of the relative URLs in the delivered document will be
        ** correct. */
        Redirect(zRealScript,301,1,410); /* LOG: redirect to add trailing / */
        return;
      }
      break;
    }
    zLine[j] = zScript[i];
    i++; j++;
  }
  zFile = StrDup(zLine);
  zPathInfo = StrDup(&zScript[i]);
  lenFile = strlen(zFile);
  zDir = StrDup(zFile);
  for(i=strlen(zDir)-1; i>0 && zDir[i]!='/'; i--){};
  if( i==0 ){
     strcpy(zDir,"/");
  }else{
     zDir[i] = 0;
  }

  /* Check to see if there is an authorization file.  If there is,
  ** process it.
  */
  sprintf(zLine, "%s/-auth", zDir);
  if( access(zLine,R_OK)==0 && !CheckBasicAuthorization(zLine) ){
    tls_close_conn();
    return;
  }

  /* Take appropriate action
  */
  if( (statbuf.st_mode & 0100)==0100 && access(zFile,X_OK)==0
      && (!(pMimeType = GetMimeType(zFile, lenFile))
          || 0==(pMimeType->flags & MTF_NOCGI)) ){ /* CGI */
    char *zBaseFilename;       /* Filename without directory prefix */
    int px[2];                 /* CGI-1 to althttpd pipe */
    int py[2];                 /* zPostData to CGI-0 pipe */

    /*
    ** Abort with an error if the CGI script is writable by anyone other
    ** than its owner.
    */
    if( statbuf.st_mode & 0022 ){
      CgiScriptWritable();
    }

    /* Compute the base filename of the CGI script */
    for(i=strlen(zFile)-1; i>=0 && zFile[i]!='/'; i--){}
    zBaseFilename = &zFile[i+1];

    /* Create pipes used to communicate with the child CGI process */
    if( pipe(px) ){
      Malfunction(440, /* LOG: pipe() failed */
                  "Unable to create a pipe for the CGI program");
    }
    if( pipe(py) ){
      Malfunction(441, /* LOG: pipe() failed */
                  "Unable to create a pipe for the CGI program");
    }        

    /* Create the child process that will run the CGI. */
    if( fork()==0 ){
      /* This code is run by the child CGI process only
      ** Begin by setting up the CGI-to-althttpd pipe */
      close(1);
      if( dup(px[1])<0 ){
        Malfunction(442, /* LOG: dup() failed */
                    "CGI cannot dup() to file descriptor 1");
      }

      /* Set up the althttpd-to-CGI link */
      close(0);
      if( dup(py[0])<0 ){
        Malfunction(444, /* LOG: dup() failed */
                  "CGI cannot dup() to file descriptor 0");
      }

      /* Close all surplus file descriptors */
      for(i=3; close(i)==0; i++){}

      /* Move into the directory holding the CGI program */
      if( chdir(zDir) ){
        char zBuf[1000];
        Malfunction(445, /* LOG: chdir() failed */
             "CGI cannot chdir to [%s] from [%s]", 
             zDir, getcwd(zBuf,999));
      }

      /* Setup the CGI environment appropriately. */
      ComputeRequestUri();
      putenv("GATEWAY_INTERFACE=CGI/1.0");
      for(i=0; i<(int)(sizeof(cgienv)/sizeof(cgienv[0])); i++){
        if( *cgienv[i].pzEnvValue ){
          SetEnv(cgienv[i].zEnvName,*cgienv[i].pzEnvValue);
        }
      }

      /* Run the CGI program */
      execl(zBaseFilename, zBaseFilename, (char*)0);
      exit(0);  /* Not reached */
    }

    /* This parent process.  The child has been started.
    ** Set up the CGI-to-althttp pipe on which to receive the reply
    */
    close(px[1]);
    in = fdopen(px[0], "rb");

    /* Set up the althttp-to-CGI pipe used to send POST data (if any) */
    close(py[0]);
    if( nPostData>0 ){
      ssize_t wrote = 0, n;
      while( nPostData>wrote ){
        n = write(py[1], zPostData+wrote, nPostData-wrote);
        if( n<=0 ) break;
        wrote += n;
      }
    }
    if( zPostData ){
       free(zPostData);
       zPostData = 0;
       nPostData = 0;
    }
    close(py[1]);
        
    /* Wait for the CGI program to reply and process that reply */
    if( in==0 ){
      CgiError();
    }else{
      CgiHandleReply(in, strncmp(zBaseFilename,"nph-",4)==0);
    }
  }else if( lenFile>5 && strcmp(&zFile[lenFile-5],".scgi")==0 ){
    /* Any file that ends with ".scgi" is assumed to be text of the
    ** form:
    **     SCGI hostname port
    ** Open a TCP/IP connection to that host and send it an SCGI request
    */
    SendScgiRequest(zFile, zScript);
  }else if( countSlashes(zRealScript)!=countSlashes(zScript) ){
    /* If the request URI for static content contains material past the
    ** actual content file name, report that as a 404 error. */
    NotFound(460); /* LOG: Excess URI content past static file name */
  }else{
    /* If it isn't executable then it must be a simple file that needs
    ** to be copied to output.
    */
    SetTimeout(30 + statbuf.st_size/2000,
               805); /* LOG: Timeout send static file */
    if( SendFile(zFile, lenFile, &statbuf) ){
      return;
    }
  }
  althttpd_fflush(stdout);
  MakeLogEntry(0, 0);  /* LOG: Normal reply */
  omitLog = 1;
}

/*
** Launch a web-browser pointing to zPage
*/
static void launch_web_browser(const char *zPath, int iPort){
  char zUrl[2000];
  static const char *const azBrowserProg[] = {
#if defined(__DARWIN__) || defined(__APPLE__) || defined(__HAIKU__)
       "open"
#else
       "xdg-open", "gnome-open", "firefox", "google-chrome"
#endif
  };
  size_t i;

  if( strlen(zPath)<=sizeof(zUrl)-1000 ){
    while( zPath[0]=='/' ) zPath++;
    sprintf(zUrl, "http://localhost:%d/%s", iPort, zPath);
    for(i=0; i<sizeof(azBrowserProg)/sizeof(azBrowserProg[0]); i++){
      execlp(azBrowserProg[i], azBrowserProg[i], zUrl, (char*)0);
    }
  }
  exit(1);
}

#define MAX_PARALLEL 50  /* Number of simultaneous children */

/*
** All possible forms of an IP address.  Needed to work around GCC strict
** aliasing rules.
*/
typedef union {
  struct sockaddr sa;              /* Abstract superclass */
  struct sockaddr_in sa4;          /* IPv4 */
  struct sockaddr_in6 sa6;         /* IPv6 */
  struct sockaddr_storage sas;     /* Should be the maximum of the above 3 */
} address;

/*
** Implement an HTTP server daemon listening on port zPort.
**
** As new connections arrive, fork a child and let the child return
** out of this procedure call.  The child will handle the request.
** The parent never returns from this procedure.
**
** Return 0 to each child as it runs.  If unable to establish a
** listening socket, return non-zero.
**
** When it accept()s a connection, the socket ID is written to the
** final argument.
*/
int http_server(
  int mnPort, int mxPort,   /* Range of TCP ports to try */
  int bLocalhost,           /* Listen on loopback sockets only */
  const char *zPage,        /* Launch web browser on this document */
  int *httpConnection       /* Socket over which HTTP request arrives */
){
  int listener = -1;           /* The server socket */
  int connection;              /* A socket for each individual connection */
  fd_set readfds;              /* Set of file descriptors for select() */
  socklen_t lenaddr;           /* Length of the inaddr structure */
  int child;                   /* PID of the child process */
  int nchildren = 0;           /* Number of child processes */
  struct timeval delay;        /* How long to wait inside select() */
  struct sockaddr_in inaddr;   /* The socket address */
  int opt = 1;                 /* setsockopt flag */
  int iPort = mnPort;

  while( iPort<=mxPort ){
    memset(&inaddr, 0, sizeof(inaddr));
    inaddr.sin_family = AF_INET;
    if( bLocalhost ){
      inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }else{
      inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    inaddr.sin_port = htons(iPort);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if( listener<0 ){
      iPort++;
      continue;
    }

    /* if we can't terminate nicely, at least allow the socket to be reused */
    setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    if( bind(listener, (struct sockaddr*)&inaddr, sizeof(inaddr))<0 ){
      close(listener);
      iPort++;
      continue;
    }
    break;
  }
  if( iPort>mxPort ){
    if( mnPort==mxPort ){
      fprintf(stderr,"unable to open listening socket on port %d\n", mnPort);
    }else{
      fprintf(stderr,"unable to open listening socket on any"
                     " port in the range %d..%d\n", mnPort, mxPort);
    }
    exit(1);
  }
  if( iPort>mxPort ) return 1;
  listen(listener,10);
  printf("Listening for %s requests on TCP port %d\n",
         useHttps?"TLS-encrypted HTTPS":"HTTP",  iPort);
  fflush(stdout);
  if( zPage ){
    child = fork();
    if( child!=0 ){
      if( child>0 ) nchildren++;
    }else{
      launch_web_browser(zPage, iPort);
      /* NOT REACHED */
      exit(1);
    }
  }
  while( 1 ){
    if( nchildren>MAX_PARALLEL ){
      /* Slow down if connections are arriving too fast */
      sleep( nchildren-MAX_PARALLEL );
    }
    delay.tv_sec = 0;
    delay.tv_usec = 100000;
    FD_ZERO(&readfds);
    assert( listener>=0 );
    FD_SET( listener, &readfds);
    select( listener+1, &readfds, 0, 0, &delay);
    if( FD_ISSET(listener, &readfds) ){
      lenaddr = sizeof(inaddr);
      connection = accept(listener, (struct sockaddr*)&inaddr, &lenaddr);
      if( connection>=0 ){
        child = fork();
        if( child!=0 ){
          if( child>0 ) nchildren++;
          close(connection);
          /* printf("subprocess %d started...\n", child); fflush(stdout); */
        }else{
          int nErr = 0, fd;
          close(0);
          fd = dup(connection);
          if( fd!=0 ) nErr++;
          close(1);
          fd = dup(connection);
          if( fd!=1 ) nErr++;
          close(connection);
          *httpConnection = fd;
          return nErr;
        }
      }
    }
    /* Bury dead children */
    while( (child = waitpid(0, 0, WNOHANG))>0 ){
      /* printf("process %d ends\n", child); fflush(stdout); */
      nchildren--;
    }
  }
  /* NOT REACHED */
  exit(1);
}

int main(int argc, const char **argv){
  int i;                     /* Loop counter */
  const char *zPermUser = 0; /* Run daemon with this user's permissions */
  int mnPort = 0;            /* Range of TCP ports for server mode */
  int mxPort = 0;
  int useChrootJail = 1;     /* True to use a change-root jail */
  struct passwd *pwd = 0;    /* Information about the user */
  int httpConnection = 0;    /* Socket ID of inbound http connection */
  int bLocalhost = 0;        /* Bind to loop-back TCP ports only */
  const char *zPage = 0;     /* Starting page */

  /* Record the time when processing begins.
  */
  gettimeofday(&beginTime, 0);

  /* Parse command-line arguments
  */
  while( argc>1 && argv[1][0]=='-' ){
    const char *z = argv[1];
    const char *zArg = argc>=3 ? argv[2] : "0";
    if( z[0]=='-' && z[1]=='-' ) z++;
    if( strcmp(z,"-root")==0 ){
      zRoot = zArg;
    }else
    if( strcmp(z,"-logfile")==0 ){
      zLogFile = zArg;
    }else
#ifdef ENABLE_TLS
    if( strcmp(z, "-cert")==0 ){
      useHttps = 2;
      zHttpScheme = "https";
      zHttps = "on";
      tlsState.zCertFile = zArg;
      if( tlsState.zKeyFile==0 ) tlsState.zKeyFile = zArg;
      if( standalone ){
        standalone = 2;
      }
    }else
    if( strcmp(z, "-pkey")==0 ){
      tlsState.zKeyFile = zArg;
    }else
#endif
    if( strcmp(z,"-user")==0 ){
      zPermUser = zArg;
    }else
    if( strcmp(z,"-ipshun")==0 ){
      zIPShunDir = zArg;
    }else
    if( strcmp(z,"-max-age")==0 ){
      mxAge = atoi(zArg);
    }else
    if( strcmp(z,"-max-cpu")==0 ){
      maxCpu = atoi(zArg);
    }else
    if( strcmp(z,"-loopback")==0 ){
      bLocalhost = 1;
    }else
    if( strcmp(z,"-page")==0 ){
      zPage = zArg;
      bLocalhost = 1;
      if( mnPort==0 ){
        mnPort = 8080;
        mxPort = 8100;
      }
      standalone = 1 + (useHttps==2);
    }else
    if( strcmp(z,"-https")==0 ){
      int const x = atoi(zArg);
      if( x<=0 ){
        useHttps = 0;
        zHttpScheme = "http";
        zHttps = 0;
      }else{
        zHttpScheme = "https";
        zHttps = "on";
        zRemoteAddr = getenv("REMOTE_HOST");
        useHttps = 1;
      }
    }else
    if( strcmp(z, "-port")==0 ){
      int ii;
      mnPort = mxPort = 0;
      for(ii=0; zArg[ii]>='0' && zArg[ii]<='9'; ii++){
        mnPort = mnPort*10 + zArg[ii] - '0';
      }
      if( zArg[ii]==0 ){
        mxPort = mnPort;
      }else if( zArg[ii]=='.' && zArg[ii+1]=='.' ){
        for(ii+=2; zArg[ii]>='0' && zArg[ii]<='9'; ii++){
          mxPort = mxPort*10 + zArg[ii] - '0';
        }
      }
      standalone = 1 + (useHttps==2);
    }else
    if( strcmp(z, "-family")==0 ){
      if( strcmp(zArg, "ipv4")==0 ){
        ipv4Only = 1;
      }else if( strcmp(zArg, "ipv6")==0 ){
        ipv6Only = 1;
      }else{
        Malfunction(513,  /* LOG: unknown IP protocol */
                    "unknown IP protocol: [%s]\n", zArg);
      }
    }else
    if( strcmp(z, "-jail")==0 ){
      if( atoi(zArg)==0 ){
        useChrootJail = 0;
      }
    }else
    if( strcmp(z, "-debug")==0 ){
      if( atoi(zArg) ){
        useTimeout = 0;
      }
    }else
    if( strcmp(z, "-input")==0 ){
      if( freopen(zArg, "rb", stdin)==0 || stdin==0 ){
        Malfunction(514, /* LOG: cannot open --input file */
                    "cannot open --input file \"%s\"\n", zArg);
      }
    }else
    if( strcmp(z, "-version")==0 ){
      puts(SERVER_SOFTWARE_TLS);
      return 0;
    }else
    if( strcmp(z, "-datetest")==0 ){
      TestParseRfc822Date();
      printf("Ok\n");
      exit(0);
    }else
    if( strcmp(z,"-remote-addr")==0 ){
      /* Used for testing purposes only - to simulate a remote IP address when
      ** input is really coming from a disk file. */
      zRemoteAddr = StrDup(zArg);
    }else
    {
      Malfunction(515, /* LOG: unknown command-line argument on launch */
                  "unknown argument: [%s]\n", z);
    }
    argv += 2;
    argc -= 2;
  }
  if( zRoot==0 ){
    if( !standalone ){
      mnPort = 8080;
      mxPort = 8100;
    }
    standalone = 1;
    bLocalhost = 1;
    zRoot = ".";
  }

  /*
  ** 10 seconds to get started
  */
  if( useTimeout ){
    signal(SIGALRM, Timeout);
    signal(SIGSEGV, Timeout);
    signal(SIGPIPE, Timeout);
    signal(SIGXCPU, Timeout);
    if( !standalone ) SetTimeout(10, 806);  /* LOG: Timeout startup */
  }

#if ENABLE_TLS
  /* We "need" to read the cert before chroot'ing to allow that the
  ** cert is stored in space outside of the --root and not readable by
  ** the --user.
  */
  if( useHttps>=2 ){
    ssl_init_server(tlsState.zCertFile, tlsState.zKeyFile);
  }
#endif

  /* Change directories to the root of the HTTP filesystem.  Then
  ** create a chroot jail there.
  */
  if( chdir(zRoot)!=0 ){
    Malfunction(517, /* LOG: chdir() failed */
                "cannot change to directory [%s]", zRoot);
  }

  /* Get information about the user if available */
  if( zPermUser ) pwd = getpwnam(zPermUser);
  else if( getuid()==0 ){
    Malfunction(518, "Cannot run as root. Use the -user USER flag.");
    return 1;
  }

  /* Enter the chroot jail if requested */  
  if( zPermUser && useChrootJail && getuid()==0 ){
    if( chroot(".")<0 ){
      Malfunction(519, /* LOG: chroot() failed */
                  "unable to create chroot jail");
    }else{
      zRoot = "";
    }
  }

  /* Activate the server, if requested */
  if( mnPort>0 && mnPort<=mxPort
   && http_server(mnPort, mxPort, bLocalhost, zPage, &httpConnection)
  ){
    Malfunction(520, /* LOG: server startup failed */
                "failed to start server");
  }

#ifdef RLIMIT_CPU
  if( maxCpu>0 ){
    struct rlimit rlim;
    rlim.rlim_cur = maxCpu;
    rlim.rlim_max = maxCpu;
    setrlimit(RLIMIT_CPU, &rlim);
  }
#endif

  /* Drop root privileges.
  */
  if( zPermUser ){
    if( pwd ){
      if( setgid(pwd->pw_gid) ){
        Malfunction(521, /* LOG: setgid() failed */
                    "cannot set group-id to %d", pwd->pw_gid);
      }
      if( setuid(pwd->pw_uid) ){
        Malfunction(522, /* LOG: setuid() failed */
                    "cannot set user-id to %d", pwd->pw_uid);
      }
    }else{
      Malfunction(523, /* LOG: unknown user */
                  "no such user [%s]", zPermUser);
    }
  }
  if( getuid()==0 ){
    Malfunction(524, /* LOG: cannot run as root */
                "cannot run as root");
  }

  /* Get the IP address from whence the request originates
  */
  if( zRemoteAddr==0 ){
    address remoteAddr;
    unsigned int size = sizeof(remoteAddr);
    char zHost[NI_MAXHOST];
    if( getpeername(0, &remoteAddr.sa, &size)>=0 ){
      getnameinfo(&remoteAddr.sa, size, zHost, sizeof(zHost), 0, 0,
                  NI_NUMERICHOST);
      zRemoteAddr = StrDup(zHost);
    }
  }
  if( zRemoteAddr!=0
   && strncmp(zRemoteAddr, "::ffff:", 7)==0
   && strchr(zRemoteAddr+7, ':')==0
   && strchr(zRemoteAddr+7, '.')!=0
  ){
    zRemoteAddr += 7;
  }
  zServerSoftware = useHttps==2 ? SERVER_SOFTWARE_TLS : SERVER_SOFTWARE;

  /* Process the input stream */
  for(i=0; i<100; i++){
    ProcessOneRequest(0, httpConnection);
  }
  ProcessOneRequest(1, httpConnection);
  tls_close_conn();
  exit(0);
}

#if 0
/* Copy/paste the following text into SQLite to generate the xref
** table that describes all error codes.
*/
BEGIN;
CREATE TABLE IF NOT EXISTS xref(lineno INTEGER PRIMARY KEY, desc TEXT);
DELETE FROM xref;
INSERT INTO xref VALUES(0,'Normal reply');
INSERT INTO xref VALUES(2,'Normal HEAD reply');
INSERT INTO xref VALUES(100,'Malloc() failed');
INSERT INTO xref VALUES(110,'Not authorized');
INSERT INTO xref VALUES(120,'CGI Error');
INSERT INTO xref VALUES(131,'SIGSEGV');
INSERT INTO xref VALUES(132,'SIGPIPE');
INSERT INTO xref VALUES(133,'SIGXCPU');
INSERT INTO xref VALUES(139,'Unknown signal');
INSERT INTO xref VALUES(140,'CGI script is writable');
INSERT INTO xref VALUES(150,'Cannot open -auth file');
INSERT INTO xref VALUES(160,' http request on https-only page');
INSERT INTO xref VALUES(170,'-auth redirect');
INSERT INTO xref VALUES(180,' malformed entry in -auth file');
INSERT INTO xref VALUES(190,'chdir() failed');
INSERT INTO xref VALUES(200,'bad protocol in HTTP header');
INSERT INTO xref VALUES(201,'URI too long');
INSERT INTO xref VALUES(210,'Empty request URI');
INSERT INTO xref VALUES(220,'Unknown request method');
INSERT INTO xref VALUES(230,'Referrer is devids.net');
INSERT INTO xref VALUES(240,'Illegal content in HOST: parameter');
INSERT INTO xref VALUES(250,'Disallowed user agent');
INSERT INTO xref VALUES(251,'Disallowed user agent (20190424)');
INSERT INTO xref VALUES(260,'Disallowed referrer');
INSERT INTO xref VALUES(270,'Request too large');
INSERT INTO xref VALUES(300,'Path element begins with "." or "-"');
INSERT INTO xref VALUES(310,'URI does not start with "/"');
INSERT INTO xref VALUES(320,'URI too long');
INSERT INTO xref VALUES(330,'Missing HOST: parameter');
INSERT INTO xref VALUES(340,'HOST parameter too long');
INSERT INTO xref VALUES(350,'*.website permissions');
INSERT INTO xref VALUES(360,'chdir() failed');
INSERT INTO xref VALUES(370,'redirect to not-found');
INSERT INTO xref VALUES(380,'URI not found');
INSERT INTO xref VALUES(390,'File not readable');
INSERT INTO xref VALUES(400,'URI is a directory w/o index.html');
INSERT INTO xref VALUES(410,'redirect to add trailing /');
INSERT INTO xref VALUES(440,'pipe() failed');
INSERT INTO xref VALUES(441,'pipe() failed');
INSERT INTO xref VALUES(442,'dup() failed');
INSERT INTO xref VALUES(444,'dup() failed');
INSERT INTO xref VALUES(445,'chdir() failed');
INSERT INTO xref VALUES(460,'Excess URI content past static file name');
INSERT INTO xref VALUES(470,'ETag Cache Hit');
INSERT INTO xref VALUES(480,'fopen() failed for static content');
INSERT INTO xref VALUES(501,'Error initializing the SSL Server');
INSERT INTO xref VALUES(502,'Error loading CERT file');
INSERT INTO xref VALUES(503,'Error loading private key file');
INSERT INTO xref VALUES(504,'Error loading self-signed cert');
INSERT INTO xref VALUES(505,'No cert');
INSERT INTO xref VALUES(506,'private key does not match cert');
INSERT INTO xref VALUES(507,'TlsServerConn');
INSERT INTO xref VALUES(508,'SSL not available');
INSERT INTO xref VALUES(509,'SSL not available');
INSERT INTO xref VALUES(510,'SSL not available');
INSERT INTO xref VALUES(512,'TLS context');
INSERT INTO xref VALUES(513,'unknown IP protocol');
INSERT INTO xref VALUES(514,'cannot open --input file');
INSERT INTO xref VALUES(515,'unknown command-line argument on launch');
INSERT INTO xref VALUES(516,'--root argument missing');
INSERT INTO xref VALUES(517,'chdir() failed');
INSERT INTO xref VALUES(519,'chroot() failed');
INSERT INTO xref VALUES(520,'server startup failed');
INSERT INTO xref VALUES(521,'setgid() failed');
INSERT INTO xref VALUES(522,'setuid() failed');
INSERT INTO xref VALUES(523,'unknown user');
INSERT INTO xref VALUES(524,'cannot run as root');
INSERT INTO xref VALUES(526,'SSL read too big');
INSERT INTO xref VALUES(527,'SSL read error');
INSERT INTO xref VALUES(528,'SSL write too big');
INSERT INTO xref VALUES(529,'Output buffer too small');
INSERT INTO xref VALUES(600,'OOM');
INSERT INTO xref VALUES(610,'OOM');
INSERT INTO xref VALUES(700,'cannot open file');
INSERT INTO xref VALUES(701,'cannot read file');
INSERT INTO xref VALUES(702,'bad SCGI spec');
INSERT INTO xref VALUES(703,'bad SCGI spec (2)');
INSERT INTO xref VALUES(704,'Unrecognized line in SCGI spec');
INSERT INTO xref VALUES(705,'Cannot resolve SCGI server name');
INSERT INTO xref VALUES(706,'bad SCGI fallback');
INSERT INTO xref VALUES(707,'Cannot open socket to SCGI');
INSERT INTO xref VALUES(708,'OOM');
INSERT INTO xref VALUES(720,'chdir() failed');
INSERT INTO xref VALUES(721,'SCGI relight failed');
INSERT INTO xref VALUES(800,'CGI Handler timeout');
INSERT INTO xref VALUES(801,'Timeout request header (1+)');
INSERT INTO xref VALUES(802,'Timeout request header (0)');
INSERT INTO xref VALUES(803,'Timeout POST data');
INSERT INTO xref VALUES(804,'Timeout decode HTTP request');
INSERT INTO xref VALUES(805,'Timeout send static file');
INSERT INTO xref VALUES(806,'Timeout startup');
INSERT INTO xref VALUES(901,'Prohibited remote IP address');
INSERT INTO xref VALUES(902,'Bashdoor attack');
#endif /* SQL */
