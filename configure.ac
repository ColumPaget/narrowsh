AC_INIT
AC_PROG_CC
AC_LANG([C])
AC_PROG_MAKE_SET
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_PROG_EGREP


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
        else
        AC_CHECK_LIB([Useful-4],GetToken,[cf_have_libUseful4=yes],[cf_have_libUseful4=no])
        AC_CHECK_HEADERS([libUseful-4/libUseful.h])
        fi
fi


if test "$cf_have_libUseful5" = "yes"
then
  echo "installed libUseful-5 found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_SUBST(LIBUSEFUL_BUNDLED,"")
  dnl Default behavior of AC_CHECK_LIB is to add the library to the LIBS variable
  dnl previous AC_CHECK_LIB don't do this, because an action is supplied for them
  AC_CHECK_LIB([Useful-5],GetToken)

        dnl openssl isn't really needed, but if it exists and we're using a system-wide libUseful, then that will
        dnl likely be linked against it
        AC_CHECK_LIB(ssl,SSL_library_init,,)
        AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
elif test "$cf_have_libUseful4" = "yes"
then
  echo "installed libUseful-4 found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_SUBST(LIBUSEFUL_BUNDLED,"")
  dnl Default behavior of AC_CHECK_LIB is to add the library to the LIBS variable
  dnl previous AC_CHECK_LIB don't do this, because an action is supplied for them
  AC_CHECK_LIB([Useful-4],GetToken)

        dnl openssl isn't really needed, but if it exists and we're using a system-wide libUseful, then that will
        dnl likely be linked against it
else
  echo "using libuseful bundled with source code"
  AC_SUBST(HAVE_LIBUSEFUL_5_LIBUSEFUL_H)
  AC_SUBST(LIBUSEFUL_BUNDLED,"libUseful-5/libUseful.a")
  AC_CONFIG_SUBDIRS([libUseful-5])
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

