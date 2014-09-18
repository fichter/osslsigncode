AC_REVISION(1.3)
AC_INIT(osslsigncode, 1.3, mfive@users.sourceforge.net)
AC_CONFIG_HEADER(config.h)

dnl Determine OS info (this changes how tests will come out, must be done first.)
DC_CHK_OS_INFO

dnl Checks for programs.
AC_PROG_CC

dnl Use -Wall if we have gcc.
dnl changequote(,)dnl
if test "x$GCC" = xyes ; then
  CFLAGS="$CFLAGS -Wall"
fi
dnl changequote([,])dnl

AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_AIX
AC_GNU_SOURCE

AC_CHECK_HEADERS(getopt.h sys/mman.h)
AC_HEADER_TIME

AC_REPLACE_FUNCS(getopt)

AC_CHECK_FUNC(mmap, AC_DEFINE(HAVE_MMAP,[1],[Define to 1 if you have mmap]), 
                    AC_MSG_ERROR([Need mmap to build.]))

dnl Require OpenSSL's libcrypto
DC_ASK_OPTLIB(crypto, PKCS7_dataFinal, openssl/pkcs7.h, [         OpenSSL Support], openssl, HAVE_OPENSSL, HAVE_OPENSSL_H, [
        AC_MSG_ERROR([OpenSSL is required. http://www.openssl.org/])
])

dnl Require Curl
DC_ASK_OPTLIB(curl, curl_easy_strerror, curl/curl.h, [            Curl Support], curl, HAVE_CURL, HAVE_CURL_H, [
        AC_MSG_WARN([Curl 7.12.0 or later is required for timestamping support. http://curl.haxx.se/])
])

AC_OUTPUT(Makefile)
