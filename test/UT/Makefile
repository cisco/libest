# source files.
SRC =  	runtest.c \
	US748/us748.c \
	US893/us893.c \
	US894/us894.c \
	US895/us895.c \
	US896/us896.c \
	US897/us897.c \
	US898/us898.c \
	US899/us899.c \
	US900/us900.c \
	US901/us901.c \
	US902/us902.c \
	US903/us903.c \
	US1005/us1005.c \
	US1159/us1159.c \
	US1060/us1060.c \
	US1864/us1864.c \
	US1883/us1883.c \
	US1884/us1884.c \
	US2174/us2174.c \
	../util/curl_utils.c \
	../util/test_utils.c \
	../util/st_server.c \
	../util/st_proxy.c \
	../util/ossl_srv.c 
OBJ = $(SRC:.c=.o)
OUT = runtest

ifndef OPENSSL_DIR
    OPENSSL_DIR=/usr/local/ssl
endif
ifndef CURL_DIR
    CURL_DIR=/usr/local/curl
endif

# include directories
INCLUDES = -I../../src/est -I../.. -I../util -I$(OPENSSL_DIR)/include -I$(CURL_DIR)/include 

# C++ compiler flags (-g -O2 -Wall)
CCFLAGS = -Wall -g -DHAVE_CUNIT -DNO_SSL_DL

# compiler
CC = gcc

# linker flags
LDFLAGS += -lcunit -ldl -lpthread -lest -lssl -lcrypto -lcurl

# library paths
LIBS = -L../../src/est/.libs -L$(OPENSSL_DIR)/lib -L$(CURL_DIR)/lib $(LDFLAGS) 


.SUFFIXES: .c

default:	runtest

.c.o:
	$(CC) $(INCLUDES) $(CCFLAGS) -c $< -o $@

runtest: $(OBJ) ../../src/est/.libs/libest.*
	$(CC) -o $(OUT) $(OBJ) $(LIBS) 

clean:
	rm -f $(OBJ)  
	rm -f runtest

