:: runserver.bat is a direct port of runserver.sh

:: Make sure the est.dll & openSSL dlls are in the %PATH%

@echo off
set EST_TRUSTED_CERTS=.\trustedcerts.crt

::set EST_TRUSTED_CERTS=.\estCA\cacertandcrl.crt

set EST_CACERTS_RESP=.\estCA\cacert.crt
set EST_OPENSSL_CACONFIG=.\estExampleCA.cnf

::set EST_CSR_ATTR=MGwGBysGAQEBARYwIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEwJwYDiDcCMSAGA4g3AxMZUGFyc2UgU0VUIGFzIDIuOTk5LjIgZGF0YQYJKyQDAwIIAQELBglghkgBZQMEAgI=

:: estserver.exe is placed by gradle under the example\build\exe\estserver 
:: directory. If it's not present here or it doesn't match the gradle
:: version then it is copied over.
set GRADLE_DIR=..\build\exe\estserver
FC /b %GRADLE_DIR%\estserver.exe .\estserver.exe > NUL
if %ERRORLEVEL% neq 0 (
    copy /b /y /v %GRADLE_DIR%\estserver.exe . > NUL
)

.\estserver -c estCA\private\estservercertandkey.pem^
 -k estCA\private\estservercertandkey.pem -r estrealm -v
