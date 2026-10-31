AC_INIT
AC_PROG_CC
AC_LANG([C])
AC_PROG_MAKE_SET
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_PROG_EGREP


dnl define a function we can use to check if a compiler flag
dnl is supported by the compiler
AC_DEFUN([CHECK_COMPILER_OPT],
[
  COMP_OPT="$@"
  AC_MSG_CHECKING([if compiler supports $COMP_OPT])
  OLD_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $COMP_OPT"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(int test() {
    return 1;
  })], [COMP_OPT_SUPPORT="yes"], [COMP_OPT_SUPPORT="no"])
  AC_MSG_RESULT([$COMP_OPT_SUPPORT])
  AS_IF([test "$COMP_OPT_SUPPORT" != "yes"], [CFLAGS="$OLD_CFLAGS"])
])


AC_ARG_ENABLE([wall],
[AS_HELP_STRING([--enable-wall], [use -Wall to get maximum compile warnings (default=no)])],
[cf_use_wall=$enableval],
[cf_use_wall=no]
)
AS_IF([test "$cf_use_wall" = "yes"], [
  CHECK_COMPILER_OPT("-Wall")
])


AC_ARG_ENABLE([werror],
[AS_HELP_STRING([--enable-werror], [treat compile warnings as errors (default=no)])],
[cf_use_werror=$enableval],
[cf_use_werror=no]
)
AS_IF([test "$cf_use_werror" = "yes"], [
  CHECK_COMPILER_OPT("-Werror")
])



AC_ARG_ENABLE([pie],
[AS_HELP_STRING([--enable-pie], [build using -fPIC for position independant code, if compiler supports it (default=yes)])],
[cf_use_pic=$enableval],
[cf_use_pic=yes]
)
AS_IF([test "$cf_use_pie" = "yes"], [
  CHECK_COMPILER_OPT("-fPIE")
])




AC_ARG_ENABLE([fortify],
[AS_HELP_STRING([--enable-fortify], [use 'FORTIFY_SOURCE=3' to harden source code (default=no)])],
[cf_use_fortify=$enableval],
[cf_use_fortify=no]
)
AC_ARG_ENABLE([stack-protect],
[AS_HELP_STRING([--enable-stack-protect], [use '-fstack-protector-strong' to harden source code (default=no)])],
[cf_use_stackprotect=$enableval],
[cf_use_stackprotect=no]
)
AC_ARG_ENABLE([harden],
[AS_HELP_STRING([--enable-harden], [use 'FORTIFY_SOURCE=3' and stack-protect to harden source code (default=no)])],
[cf_use_harden=$enableval],
[cf_use_harden=no]
)




AC_ARG_ENABLE(nosu, [  --enable-nosu           use prctl to set 'no new privs' preventing su/sudo (default=yes) ], cf_use_nosu=$enableval, cf_use_nosu="yes" )
AC_ARG_ENABLE(namespaces, [  --enable-namespaces     use linux namespaces (default=auto) ], cf_use_namespaces=$enableval, cf_use_namespaces="yes" )
AC_ARG_WITH(libuseful, [  --with-libuseful              use system-wide libUseful (default=auto) ], cf_system_libuseful=$withval )


AC_SYS_LARGEFILE
AC_CHECK_LIB(ssl,SSL_library_init,,)
AC_CHECK_LIB(ssl,OPENSSL_init_ssl,,)
AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_new,,)
AC_CHECK_LIB(cap,cap_init,,)
AC_CHECK_LIB(z,deflate,,)


AS_IF([test "$cf_use_harden" = "yes"],
[
  cf_use_fortify="yes"
  cf_use_stackprotect="yes"

  CHECK_COMPILER_OPT("-ftrivial-auto-var-init=zero")
  CHECK_COMPILER_OPT("-fstack-clash-protection")
  CHECK_COMPILER_OPT("-fno-strict-overflow")
  CHECK_COMPILER_OPT("-fno-strict-aliasing")
  CHECK_COMPILER_OPT("-fno-delete-null-pointer-checks")
  CHECK_COMPILER_OPT("-fcf-protection=full")
  CHECK_COMPILER_OPT("-mmitigate-rop")
  CHECK_COMPILER_OPT("-fhardened")
])


AS_IF([test "$cf_use_fortify" = "yes"], [
CFLAGS="$CFLAGS -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
])

AS_IF([test "$cf_use_stackprotect" = "yes"], [
CHECK_COMPILER_OPT("-fstack-protector-strong")
AS_IF([test "$COMP_OPT_SUPPORT" != "yes"], [cf_use_stackprotect="no"])
])




if test "$cf_use_namespaces" != "no"
then
AC_CHECK_LIB(c,unshare,cf_use_namespaces="yes",,cf_use_namespaces="no")
fi



if test "$cf_system_libuseful" != "no"
then
        AC_CHECK_LIB([Useful-5],GetToken,[cf_have_libUseful5=yes],[cf_have_libUseful5=no])
        if test "$cf_have_libUseful5" = "yes"
        then
        AC_CHECK_HEADERS([libUseful-5/libUseful.h])
        fi
fi


if test "$cf_have_libUseful5" = "yes"
then
  echo "installed libUseful-5 found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_SUBST(LIBUSEFUL_BUNDLED,"")
  AC_DEFINE(HAVE_LIBUSEFUL)
  dnl Default behavior of AC_CHECK_LIB is to add the library to the LIBS variable
  dnl previous AC_CHECK_LIB don't do this, because an action is supplied for them
  AC_CHECK_LIB([Useful-5],GetToken)

        dnl openssl isn't really needed, but if it exists and we're using a system-wide libUseful, then that will
        dnl likely be linked against it
        AC_CHECK_LIB(ssl,SSL_library_init,,)
        AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
else
  echo "using libuseful bundled with source code"
  AC_SUBST(HAVE_LIBUSEFUL_5_LIBUSEFUL_H)
  AC_SUBST(LIBUSEFUL_BUNDLED,"libUseful-bundled/libUseful.a")
  AC_CONFIG_SUBDIRS([libUseful-bundled])
fi


if test "$cf_use_nosu" = "yes"
then
AC_CHECK_HEADER([sys/prctl.h],cf_have_prctl="yes",,)
fi


if test "$cf_use_nosu" = "yes"
then 
  if test "$cf_have_prctl" = "yes"
  then
        AC_DEFINE([USE_NO_NEW_PRIVS])
	echo "using prctl(PR_SET_NO_NEW_PRIVS) to control su/sudo/suid"
  else
	echo "unable to find prctl.h, control of su/sudo/suid will not be possible"
  fi
else
echo "disabled prctl(PR_SET_NO_NEW_PRIVS) to control su/sudo/suid"
fi

if test "$cf_use_namespaces" = "yes"
then
AC_DEFINE([USE_NAMESPACES])
echo "using linux namespaces for nonet, noipc, nopid, and hostname options"
else
echo "linux namespaces disabled or unavailable, no support for nonet, noipc, nopid, and hostname options"
fi



AC_CONFIG_FILES([Makefile])
AC_OUTPUT

