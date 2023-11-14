# Display exported symbols:
#  nm -D empty-pkcs11.so | grep ' T '

ARCH := $(shell getconf LONG_BIT)

SRC_DIR=./src
INC_DIR=./include

CC= gcc
CPP_FLAGS_32 := -m32
CPP_FLAGS_64 := -m64
CFLAGS= $(CPP_FLAGS_$(ARCH)) -Wall -Wextra -Wno-unused-parameter -g -O0 -I$(INC_DIR)

LIBNAME=trustnsign-pkcs11-x$(ARCH).so

all: pkcs11.o rest_interface.o base64.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,lib.version \
	pkcs11.o rest_interface.o base64.o -lcurl -ljson-c
#strip --strip-all $(LIBNAME)

pkcs11.o: $(SRC_DIR)/pkcs11.c
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/pkcs11.c

rest_interface.o: $(SRC_DIR)/rest_interface.c
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/rest_interface.c

base64.o: $(SRC_DIR)/base64.c
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/base64.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so
