# source files.
SRC =  	../../util/curl_utils.c
OBJ = $(SRC:.c=.o)

ifndef OPENSSL_DIR
    OPENSSL_DIR=/usr/local/ssl
endif
ifndef CURL_DIR
    CURL_DIR=/usr/local/curl
endif

# include directories
INCLUDES = -I../../../src/est -I../../util -I$(OPENSSL_DIR)/include -I$(CURL_DIR)/include 

# C++ compiler flags (-g -O2 -Wall)
CCFLAGS = -Wall -DNO_SSL_DL

# compiler
CC = gcc

# library paths
LIBS = -L../../../src/est/.libs -L$(OPENSSL_DIR)/lib -L$(CURL_DIR)/lib -ldl -lpthread -lssl -lcrypto -lest -lcurl 

# compile flags
LDFLAGS = 

.SUFFIXES: .c

.c.o:
	$(CC) $(INCLUDES) $(CCFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)  
	rm -f perftest

