:: ############################################################################
:: Program: createRA.bat
::
:: Direct port of createRA.sh
::
:: ############################################################################

:: default variables and config options
@echo off
set EST_SCRIPTNAME=%0
set EST_OPENSSL_CACNF=.\estExampleCA.cnf
set EST_SERVER_SUBJ=/CN=127.0.0.1
set EST_SERVER_CERTREQ=tmp\proxy-csr.pem
set EST_SERVER_CERT=proxy-cert.pem
set EST_SERVER_KEY=proxy-key.pem
set EST_ECPARMS=tmp\ec.pem
set OPENSSLCMD=openssl
set RETURN_CODE=0

:: Create a temp directory
if exist tmp\NUL ( 
    rmdir /s /q tmp 
)
mkdir tmp


call %OPENSSLCMD% ecparam -out %EST_ECPARMS% -name prime256v1 -genkey
call %OPENSSLCMD% ecparam -in %EST_ECPARMS% -check

:: Create a certificate for our est server
:: TODO: add extension for est server
echo #################################################################
echo ####(Re)creating a certificate for our RA to use
echo #################################################################
:: re-using the same NEWKEY_PARAM as is used for our CA
call %OPENSSLCMD% req -new -nodes -out %EST_SERVER_CERTREQ% -newkey ec:%EST_ECPARMS%^
 -keyout %EST_SERVER_KEY% -subj %EST_SERVER_SUBJ% -config %EST_OPENSSL_CACNF%
if %ERRORLEVEL% neq 0 (
    set ERROR_MSG=Unable to create est server CSR
    goto :errorlog
)

call %OPENSSLCMD% ca -out %EST_SERVER_CERT% -batch -config %EST_OPENSSL_CACNF%^
 -infiles %EST_SERVER_CERTREQ%
if %ERRORLEVEL% neq 0 (
    set ERROR_MSG=Unable to create RA certificate
    goto :errorlog
)

call %OPENSSLCMD% x509 -in %EST_SERVER_CERT% -text

goto :script_complete

:errorlog
    set RETURN_CODE=1
    echo ###########..EXIT..##########
    echo SCRIPT %EST_SCRIPTNAME% EXIT: %ERROR_MSG% (%RETURN_CODE%)
    echo ###########^^^^EXIT^^^^##########
    echo.

:script_complete
exit /b %RETURN_CODE%
