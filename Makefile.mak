# Makefile für Microsoft Visual Studio C
# Tested with version 11.0 (2012)
# Usage: in a VS2011 Native Tools Command Prompt shell, execute 
# vsvars32.bat
# nmake -f Makefile.mak 



# Set your compiler options
PLATFORM=VC-WIN32
OPENSSL=D:/sys/software/openssl-1.0.2d-Win32
CC=cl
#/I"C:/Program Files (x86)/Microsoft SDKs/Windows/v7.1A/Include" 
CFLAG= /D_X86_ /DDISABLE_BACKTRACE /I"C:/Program Files (x86)/Windows Kits/8.0/Include/shared"  /I"C:/Program Files (x86)/Windows Kits/8.0/Include/um" /I$(OPENSSL)/include /TP /Od -DDEBUG -D_DEBUG /UDSO_WIN32 /D__WM_DEBUG__ /DNO_STRINGS_H /DMONOLITH /D_UNICODE /DUNICODE /FD /EHsc /MDd /Zp1 /GS- /W3 /D_CRT_SECURE_NO_WARNINGS /nologo /c /Zi /wd4127  
APP_CFLAG= /Fd$(TMP_D)/app
LIB_CFLAG=/Zl /Fd$(TMP_D)/lib
SHLIB_CFLAG=
SHLIB_EX_OBJ=
# add extra libraries to this define, for solaris -lsocket -lnsl would
# be added
EX_LIBS=libeay32.lib ssleay32.lib pthread.lib ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib msvcrtd.lib  
#MSVCRT(D) is needed to avoid error LNK2001: unresolved external symbol _mainCRTStartup

LINK=link
LFLAGS=/STACK:8000000 /nologo /subsystem:console /opt:ref /DEBUG /MACHINE:x86 /LIBPATH:$(OPENSSL)/lib /LIBPATH:.

RSC=rc

# The output directory for all the temporary muck
TMP_D=tmp32.dbg

CP=copy
RM=del /Q
RANLIB=
MKDIR=mkdir
MKLIB=lib /nologo
MLFLAGS=
ASM=ml /nologo /Cp /coff /c /Cx /Z7


######################################################
# You should not need to touch anything below this point
######################################################

# The libest directory
SRC_D=src/est
UTIL_SRC_D=example/util

ESTCLIENT = example\client\estclient
ESTCLIENT_SIMPLE = example\client-simple\estclient-simple
ESTPROXY = example\proxy\estproxy
ESTSERVER = example\server\estserver
APPS_EXE = $(ESTCLIENT).exe $(ESTCLIENT_SIMPLE).exe $(ESTPROXY).exe $(ESTSERVER).exe


# LIB_D  - library output directory
# Note: if you change these point to different directories then uncomment out
# the lines around the 'NB' comment below.
# 
LIB_D=src\est\.libs

# OBJ_D  - temp object file directory
OBJ_D=$(TMP_D)

LIBEST = libest
O_LIBEST=     $(LIB_D)/$(LIBEST).lib
SO_LIBEST=    $(LIBEST)
L_LIBEST=     $(LIB_D)/$(LIBEST).lib


INC=/I. /Isrc/est
APP_CFLAGS=$(INC) $(CFLAG) $(APP_CFLAG)
LIB_CFLAGS=$(INC) $(CFLAG) $(LIB_CFLAG)
SHLIB_CFLAGS=$(INC) $(CFLAG) $(LIB_CFLAG) $(SHLIB_CFLAG)
LIBS_DEP=$(O_LIBEST)

#############################################
HEADER=
EXHEADER=
T_OBJ=
EC_OBJ = $(OBJ_D)/estclient.obj
ECS_OBJ = $(OBJ_D)/estclient_simple.obj
EP_OBJ = $(OBJ_D)/estproxy.obj
ES_OBJ = $(OBJ_D)/estserver.obj
EC_EX_OBJ = $(OBJ_D)/utils.obj
ES_EX_OBJ = $(OBJ_D)/utils.obj $(OBJ_D)/ossl_srv.obj
LIBEST_OBJS=$(OBJ_D)/est.obj \
	$(OBJ_D)/est_client.obj $(OBJ_D)/est_client_http.obj $(OBJ_D)/est_ossl_util.obj \
	$(OBJ_D)/est_proxy.obj $(OBJ_D)/est_server.obj $(OBJ_D)/est_server_http.obj \
	$(OBJ_D)/NonPosix.obj $(OBJ_D)/simple_server.obj 


E_SHLIB=

###################################################################
all: banner $(TMP_D) $(LIB_D) lib exe 

banner:
	@echo Building libest

$(TMP_D):
	$(MKDIR) "$(TMP_D)"

$(LIB_D):
	$(MKDIR) "$(LIB_D)"

headers: $(HEADER) $(EXHEADER)

lib: $(LIBS_DEP)

exe: $(APPS_EXE)


clean:
	$(RM) $(TMP_D)\*.*

vclean: clean
	$(RM) $(APPS_EXE)
	$(RM) $(LIB_D)\*.*

reallyclean: vclean
	$(RM) -rf $(TMP_D)
	$(RM) -rf $(LIB_D)

$(OBJ_D)/est.obj: $(SRC_D)/est.c
	$(CC) /Fo$(OBJ_D)/est.obj $(APP_CFLAGS) -c $(SRC_D)/est.c

$(OBJ_D)/est_client.obj: $(SRC_D)/est_client.c
	$(CC) /Fo$(OBJ_D)/est_client.obj $(APP_CFLAGS) -c $(SRC_D)/est_client.c

$(OBJ_D)/est_client_http.obj: $(SRC_D)/est_client_http.c
	$(CC) /Fo$(OBJ_D)/est_client_http.obj $(APP_CFLAGS) -c $(SRC_D)/est_client_http.c

$(OBJ_D)/est_ossl_util.obj: $(SRC_D)/est_ossl_util.c
	$(CC) /Fo$(OBJ_D)/est_ossl_util.obj $(APP_CFLAGS) -c $(SRC_D)/est_ossl_util.c

$(OBJ_D)/est_proxy.obj: $(SRC_D)/est_proxy.c
	$(CC) /Fo$(OBJ_D)/est_proxy.obj $(APP_CFLAGS) -c $(SRC_D)/est_proxy.c

$(OBJ_D)/est_server.obj: $(SRC_D)/est_server.c
	$(CC) /Fo$(OBJ_D)/est_server.obj $(APP_CFLAGS) -c $(SRC_D)/est_server.c

$(OBJ_D)/est_server_http.obj: $(SRC_D)/est_server_http.c
	$(CC) /Fo$(OBJ_D)/est_server_http.obj $(APP_CFLAGS) -c $(SRC_D)/est_server_http.c

$(OBJ_D)/NonPosix.obj: $(SRC_D)/NonPosix.c
	$(CC) /Fo$(OBJ_D)/NonPosix.obj $(APP_CFLAGS) -c $(SRC_D)/NonPosix.c

#$(OBJ_D)/est_highlevel.obj: $(SRC_D)/est_highlevel.c
#	$(CC) /Fo$(OBJ_D)/est_highlevel.obj $(APP_CFLAGS) -c $(SRC_D)/est_highlevel.c
#
$(OBJ_D)/simple_server.obj: $(UTIL_SRC_D)/simple_server.c
	$(CC) /Fo$(OBJ_D)/simple_server.obj $(APP_CFLAGS) -c $(UTIL_SRC_D)/simple_server.c

$(OBJ_D)/ossl_srv.obj: $(UTIL_SRC_D)/ossl_srv.c
	$(CC) /Fo$(OBJ_D)/ossl_srv.obj $(APP_CFLAGS) -c $(UTIL_SRC_D)/ossl_srv.c

$(OBJ_D)/utils.obj: $(UTIL_SRC_D)/utils.c
	$(CC) /Fo$(OBJ_D)/utils.obj $(APP_CFLAGS) -c $(UTIL_SRC_D)/utils.c

$(EC_OBJ): $(ESTCLIENT).c
	@echo Building estclient
	$(CC) /Fo$(EC_OBJ) $(APP_CFLAGS) -c $(ESTCLIENT).c

$(ECS_OBJ): $(ESTCLIENT_SIMPLE).c
	@echo Building estclient_simple
	$(CC) /Fo$(ECS_OBJ) $(APP_CFLAGS) -c $(ESTCLIENT_SIMPLE).c

$(EP_OBJ): $(ESTPROXY).c
	@echo Building estproxy
	$(CC) /Fo$(EP_OBJ) $(APP_CFLAGS) -c $(ESTPROXY).c

$(ES_OBJ): $(ESTSERVER).c
	@echo Building estserver
	$(CC) /Fo$(ES_OBJ) $(APP_CFLAGS) -c $(ESTSERVER).c

$(O_LIBEST): $(LIBEST_OBJS)
	$(MKLIB) /out:$(O_LIBEST) @<<
  $(LIBEST_OBJS)
<<

$(ESTCLIENT).exe: $(EC_OBJ) $(EC_EX_OBJ) $(LIBS_DEP)
	@echo Linking estclient
	$(LINK) $(LFLAGS) /out:$(ESTCLIENT).exe $(EC_OBJ) $(EC_EX_OBJ) $(L_LIBEST) $(EX_LIBS)

$(ESTCLIENT_SIMPLE).exe: $(ECS_OBJ) $(EC_EX_OBJ) $(LIBS_DEP)
	@echo Linking estclient_simple
	$(LINK) $(LFLAGS) /out:$(ESTCLIENT_SIMPLE).exe $(ECS_OBJ) $(EC_EX_OBJ) $(L_LIBEST) $(EX_LIBS)

$(ESTPROXY).exe: $(EP_OBJ) $(ES_EX_OBJ) $(LIBS_DEP)
	@echo Linking estproxy
	$(LINK) $(LFLAGS) /out:$(ESTPROXY).exe $(EP_OBJ) $(ES_EX_OBJ) $(L_LIBEST) $(EX_LIBS)

$(ESTSERVER).exe: $(ES_OBJ) $(ES_EX_OBJ) $(LIBS_DEP)
	@echo Linking estclient
	$(LINK) $(LFLAGS) /out:$(ESTSERVER).exe $(ES_OBJ) $(ES_EX_OBJ) $(L_LIBEST) $(EX_LIBS)

