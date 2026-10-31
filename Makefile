LIBS=-lz -lcap -lcrypto -lcrypto -lssl -lssl 
FLAGS=-DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -D_FILE_OFFSET_BITS=64 -DHAVE_LIBSSL=1 -DHAVE_LIBSSL=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCAP=1 -DHAVE_LIBZ=1 -DUSE_NO_NEW_PRIVS=1 -DUSE_NAMESPACES=1 -g -O2 -ftrivial-auto-var-init=zero -fstack-clash-protection -fno-strict-overflow -fno-strict-aliasing -fno-delete-null-pointer-checks -mmitigate-rop -fhardened -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong

all: libUseful-bundled/libUseful.a
	gcc $(FLAGS) -onarrowsh main.c -lz -lcap -lcrypto -lcrypto -lssl -lssl  libUseful-bundled/libUseful.a

libUseful-bundled/libUseful.a:
	$(MAKE) -C libUseful-bundled

clean:
	rm *.o *.orig .*.swp */*.o */*.a */*.so
