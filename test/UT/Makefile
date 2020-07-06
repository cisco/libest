#ENABLE_BRSKI=1
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
	US1060/us1060c.c \
	US1190/us1190.c \
	US1864/us1864.c \
	US1883/us1883.c \
	US1884/us1884.c \
	US2174/us2174.c \
	US3496/us3496.c \
	US3512/us3512.c \
	US3612/us3612.c \
	US3646/us3646.c \
	US4020/us4020.c \
	US4710/us4710.c \
	US4778/us4778.c \
	US4784/us4784.c \
	US4752/us4752.c \
	US4880/us4880.c \
	US5052/us5052.c \
	US5121/us5121.c \
	US5139/us5139.c \
	US5184/us5184.c \
	US5213/us5213.c \
	US5226/us5226.c \
	US5230/us5230.c \
	US5237/us5237.c \
	US5240/us5240.c \
	US5241/us5241.c \
	US5244/us5244.c \
	US5246/us5246.c \
	US5248/us5248.c \
	US5255/us5255.c \
	US5282/us5282.c \
	US5331/us5331.c \
	US5357/us5357.c \
	US5367/us5367.c \
	US5394/us5394.c \
	US5399/us5399.c \
	US5418/us5418c.c \
	US5418/us5418h.c \
	../util/cdets.c \
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
    CURL_CC_DEFINE = 
else 
    CURL_CC_DEFINE = -DHAVE_LIBCURL
endif
ifndef CISCOSAFEC_DIR
    CISCOSAFEC_DIR=/usr/local/ciscosafec/
endif
ifndef URIPARSER_DIR
    URIPARSER_LDFLAGS=
else
    URIPARSER_LDFLAGS=-luriparser
	CFLAGS+=-DENABLE_URIPARSER
endif
ifndef CUNIT_DIR
   CUNIT_DIR=/usr/local
endif
ifdef LIBCOAP_DIR
	CFLAGS+=-DHAVE_LIBCOAP
	CFLAGS+=-DLIBCOAP_DIR=\"$(LIBCOAP_DIR)\"
endif
ifdef ENABLE_BRSKI
	CFLAGS+=-DENABLE_BRSKI
endif    

# include directories
INCLUDES = -I../../src/est -I../.. -I../util -I$(OPENSSL_DIR)/include -I$(CURL_DIR)/include -I$(CUNIT_DIR)/include -I$(URIPARSER_DIR)/include -I$(LIBCOAP_DIR)/include

# C++ compiler flags (-g -O2 -Wall)
CCFLAGS = -Wall -g -DHAVE_CUNIT -DNO_SSL_DL $(CURL_CC_DEFINE) $(CFLAGS) 

# compiler
CC = gcc

# linker flags
LDFLAGS += -lcunit -ldl -lpthread -lssl -lcrypto -lest -lcurl $(URIPARSER_LDFLAGS)

# library paths
LIBS = -L../../src/est/.libs -L$(URIPARSER_DIR)/lib -L$(OPENSSL_DIR)/lib -L$(CURL_DIR)/lib -L$(CUNIT_DIR)/lib $(LDFLAGS)




.SUFFIXES: .c

default:	runtest

.c.o:
	$(CC) $(INCLUDES) $(CCFLAGS) -c $< -o $@

runtest: $(OBJ)
	$(CC) -o $(OUT) $(OBJ) $(LIBS) 

clean:
	rm -f $(OBJ)  
	rm -f runtest
