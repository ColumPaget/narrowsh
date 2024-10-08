LIBS=-lUseful-5 -lz -lcrypto -lssl 
FLAGS=-DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DHAVE_LIBSSL=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBZ=1 -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_LIBUSEFUL_5_LIBUSEFUL_H=1 -DHAVE_LIBUSEFUL_5=1 -DUSE_NO_NEW_PRIVS=1 -DUSE_NAMESPACES=1

all: 
	gcc $(FLAGS) -onarrowsh main.c -lUseful-5 -lz -lcrypto -lssl  

:
	$(MAKE) -C libUseful-5

clean:
	rm *.o *.orig .*.swp */*.o */*.a */*.so
