# Makefile für Microsoft Visual Studio C
# Tested with version 11.0 (2012)
# Usage: in a VS2011 Native Tools Command Prompt shell, execute 
# ..\..\vsvars32.bat
# nmake -f Makefile.mak 



# Set your compiler options
PLATFORM=VC-WIN32
OPENSSL=D:/sys/software/openssl-1.0.2d-Win32
CUNIT_INC=D:/sys/software/CUnit-2.1-3
CURL=D:/sys/software/curl-7.36.0
CC=cl
CFLAG= /D_X86_ /DDISABLE_BACKTRACE /DHAVE_CUNIT /I"C:/Program Files (x86)/Windows Kits/8.0/Include/shared"  /I"C:/Program Files (x86)/Windows Kits/8.0/Include/um" /I$(OPENSSL)/include /I$(CUNIT_INC) /I$(CURL)/include /TP /Od -DDEBUG -D_DEBUG /UDSO_WIN32 /D__WM_DEBUG__ /DNO_STRINGS_H /DMONOLITH /D_UNICODE /DUNICODE /FD /EHsc /MDd /Zp1 /GS- /W3 /D_CRT_SECURE_NO_WARNINGS /nologo /c /Zi /wd4127  
APP_CFLAG= /Fd$(TMP_D)/app
LIB_CFLAG=/Zl /Fd$(TMP_D)/lib

# add extra libraries to this define, for solaris -lsocket -lnsl would
# be added
EX_LIBS=libeay32.lib ssleay32.lib libcunit.lib libcurl.lib pthread.lib ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib msvcrtd.lib libmingwex.a libgcc.a 
#MSVCRT(D) is needed to avoid error LNK2001: unresolved external symbol _mainCRTStartup
#libmingwex.a and libgcc.a are needed if libcunit.lib was build with MinGW tools

LINK=link
LFLAGS=/STACK:8000000 /nologo /subsystem:console /opt:ref /DEBUG /MACHINE:x86 /LIBPATH:$(OPENSSL)/lib /LIBPATH:.

RSC=rc

# The output directory for all the temporary muck
TMP_D=tmp32.dbg

CP=copy
RM=del /Q
RANLIB=
MKDIR=mkdir
MLFLAGS=
ASM=ml /nologo /Cp /coff /c /Cx /Z7


######################################################
# You should not need to touch anything below this point
######################################################

UTIL_SRC_D=../../example/util
TEST_SRC_D=../util
SRC_D=.

RUNTEST = runtest
APPS_EXE = $(RUNTEST).exe


# LIB_D  - library output directory
# Note: if you change these point to different directories then uncomment out
# the lines around the 'NB' comment below.
# 
LIB_D=../../src/est/.libs

# OBJ_D  - temp object file directory
OBJ_D=$(TMP_D)

LIBEST = libest
L_LIBEST=     $(LIB_D)/$(LIBEST).lib


INC=/I../util /I../.. /I../../src/est
APP_CFLAGS=$(INC) $(CFLAG) /DCURL_PULL_WS2TCPIP_H $(APP_CFLAG)
LIB_CFLAGS=$(INC) $(CFLAG) $(LIB_CFLAG)

#############################################
HEADER=
EXHEADER=
T_OBJ=
RT_OBJ = $(OBJ_D)/runtest.obj
RT_EX_OBJ = $(OBJ_D)/curl_utils.obj $(OBJ_D)/test_utils.obj $(OBJ_D)/st_server.obj $(OBJ_D)/st_proxy.obj $(OBJ_D)/ossl_srv.obj $(OBJ_D)/simple_server.obj 
TEST_OBJS=$(OBJ_D)/us748.obj $(OBJ_D)/us893.obj $(OBJ_D)/us894.obj $(OBJ_D)/us895.obj $(OBJ_D)/us896.obj \
	 $(OBJ_D)/us897.obj $(OBJ_D)/us898.obj $(OBJ_D)/us899.obj \
	 $(OBJ_D)/us900.obj $(OBJ_D)/us901.obj $(OBJ_D)/us902.obj $(OBJ_D)/us903.obj \
	 $(OBJ_D)/us1005.obj $(OBJ_D)/us1060.obj $(OBJ_D)/us1159.obj \
	 $(OBJ_D)/us1864.obj $(OBJ_D)/us1883.obj $(OBJ_D)/us1884.obj $(OBJ_D)/us2174.obj 
	


###################################################################
all: banner $(TMP_D) exe 

banner:
	@echo Building runtest

$(TMP_D):
	$(MKDIR) "$(TMP_D)"

exe: $(APPS_EXE)


clean:
	$(RM) $(TMP_D)\*.*

vclean: clean
	$(RM) $(APPS_EXE)

reallyclean: vclean
	$(RM) -rf $(TMP_D)

$(OBJ_D)/us748.obj: US748/us748.c
	$(CC) /Fo$(OBJ_D)/us748.obj $(APP_CFLAGS) -c US748/us748.c

$(OBJ_D)/us893.obj: US893/us893.c
	$(CC) /Fo$(OBJ_D)/us893.obj $(APP_CFLAGS) -c US893/us893.c

$(OBJ_D)/us894.obj: US894/us894.c
	$(CC) /Fo$(OBJ_D)/us894.obj $(APP_CFLAGS) -c US894/us894.c

$(OBJ_D)/us895.obj: US895/us895.c
	$(CC) /Fo$(OBJ_D)/us895.obj $(APP_CFLAGS) -c US895/us895.c

$(OBJ_D)/us896.obj: US896/us896.c
	$(CC) /Fo$(OBJ_D)/us896.obj $(APP_CFLAGS) -c US896/us896.c

$(OBJ_D)/us897.obj: US897/us897.c
	$(CC) /Fo$(OBJ_D)/us897.obj $(APP_CFLAGS) -c US897/us897.c

$(OBJ_D)/us898.obj: US898/us898.c
	$(CC) /Fo$(OBJ_D)/us898.obj $(APP_CFLAGS) -c US898/us898.c

$(OBJ_D)/us899.obj: US899/us899.c
	$(CC) /Fo$(OBJ_D)/us899.obj $(APP_CFLAGS) -c US899/us899.c

$(OBJ_D)/us900.obj: US900/us900.c
	$(CC) /Fo$(OBJ_D)/us900.obj $(APP_CFLAGS) -c US900/us900.c

$(OBJ_D)/us901.obj: US901/us901.c
	$(CC) /Fo$(OBJ_D)/us901.obj $(APP_CFLAGS) -c US901/us901.c

$(OBJ_D)/us902.obj: US902/us902.c
	$(CC) /Fo$(OBJ_D)/us902.obj $(APP_CFLAGS) -c US902/us902.c

$(OBJ_D)/us903.obj: US903/us903.c
	$(CC) /Fo$(OBJ_D)/us903.obj $(APP_CFLAGS) -c US903/us903.c

$(OBJ_D)/us1005.obj: US1005/us1005.c
	$(CC) /Fo$(OBJ_D)/us1005.obj $(APP_CFLAGS) -c US1005/us1005.c

$(OBJ_D)/us1060.obj: US1060/us1060.c
	$(CC) /Fo$(OBJ_D)/us1060.obj $(APP_CFLAGS) -c US1060/us1060.c

$(OBJ_D)/us1159.obj: US1159/us1159.c
	$(CC) /Fo$(OBJ_D)/us1159.obj $(APP_CFLAGS) -c US1159/us1159.c

$(OBJ_D)/us1864.obj: US1864/us1864.c
	$(CC) /Fo$(OBJ_D)/us1864.obj $(APP_CFLAGS) -c US1864/us1864.c

$(OBJ_D)/us1883.obj: US1883/us1883.c
	$(CC) /Fo$(OBJ_D)/us1883.obj $(APP_CFLAGS) -c US1883/us1883.c

$(OBJ_D)/us1884.obj: US1884/us1884.c
	$(CC) /Fo$(OBJ_D)/us1884.obj $(APP_CFLAGS) -c US1884/us1884.c

$(OBJ_D)/us2174.obj: US2174/us2174.c
	$(CC) /Fo$(OBJ_D)/us2174.obj $(APP_CFLAGS) -c US2174/us2174.c

$(OBJ_D)/est_client.obj: $(SRC_D)/est_client.c
	$(CC) /Fo$(OBJ_D)/est_client.obj $(APP_CFLAGS) -c $(SRC_D)/est_client.c

$(OBJ_D)/simple_server.obj: $(UTIL_SRC_D)/simple_server.c
	$(CC) /Fo$(OBJ_D)/simple_server.obj $(APP_CFLAGS) -c $(UTIL_SRC_D)/simple_server.c

$(OBJ_D)/ossl_srv.obj: $(UTIL_SRC_D)/ossl_srv.c
	$(CC) /Fo$(OBJ_D)/ossl_srv.obj $(APP_CFLAGS) -c $(UTIL_SRC_D)/ossl_srv.c

$(OBJ_D)/curl_utils.obj: $(TEST_SRC_D)/curl_utils.c
	$(CC) /Fo$(OBJ_D)/curl_utils.obj $(APP_CFLAGS) -c $(TEST_SRC_D)/curl_utils.c

$(OBJ_D)/test_utils.obj: $(TEST_SRC_D)/test_utils.c
	$(CC) /Fo$(OBJ_D)/test_utils.obj $(APP_CFLAGS) -c $(TEST_SRC_D)/test_utils.c

$(OBJ_D)/st_server.obj: $(TEST_SRC_D)/st_server.c
	$(CC) /Fo$(OBJ_D)/st_server.obj $(APP_CFLAGS) -c $(TEST_SRC_D)/st_server.c

$(OBJ_D)/st_proxy.obj: $(TEST_SRC_D)/st_proxy.c
	$(CC) /Fo$(OBJ_D)/st_proxy.obj $(APP_CFLAGS) -c $(TEST_SRC_D)/st_proxy.c

$(RT_OBJ): $(RUNTEST).c ../../src/est/.libs/libest.lib
	@echo Compiling runtest
	$(CC) /Fo$(RT_OBJ) $(APP_CFLAGS) -c $(RUNTEST).c

$(RUNTEST).exe: $(RT_OBJ) $(RT_EX_OBJ) $(TEST_OBJS) $(LIBS_DEP)
	@echo Linking runtest
	$(LINK) $(LFLAGS) /out:$(RUNTEST)1.exe $(RT_OBJ) $(RT_EX_OBJ) $(TEST_OBJS) $(L_LIBEST) $(EX_LIBS)

