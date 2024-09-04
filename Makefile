LIBS=-lz -lcap -lcrypto -lcrypto -lssl -lssl 
FLAGS=-DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -D_FILE_OFFSET_BITS=64 -DHAVE_LIBSSL=1 -DHAVE_LIBSSL=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCAP=1 -DHAVE_LIBZ=1 -DUSE_NO_NEW_PRIVS=1

all: libUseful-5/libUseful.a
	gcc $(FLAGS) -onarrowsh main.c -lz -lcap -lcrypto -lcrypto -lssl -lssl  libUseful-5/libUseful.a

libUseful-5/libUseful.a:
	$(MAKE) -C libUseful-5

clean:
	rm *.o *.orig .*.swp */*.o */*.a */*.so
