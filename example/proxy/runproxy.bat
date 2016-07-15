:: runproxy.bat is a direct port of runproxy.sh

:: Make sure the est.dll & openSSL dlls are in the %PATH%

@echo off
set EST_TRUSTED_CERTS=..\server\trustedcerts.crt
set EST_CACERTS_RESP=..\server\estCA\cacert.crt

:: estproxy.exe is placed by gradle under the example\build\exe\estproxy 
:: directory. If it's not present here or it doesn't match the gradle
:: version then it is copied over.
set GRADLE_DIR=..\build\exe\estproxy
FC /b %GRADLE_DIR%\estproxy.exe .\estproxy.exe > NUL
if %ERRORLEVEL% neq 0 (
    copy /b /y /v %GRADLE_DIR%\estproxy.exe . > NUL
)

.\estproxy -c .\proxy-cert.pem -k .\proxy-key.pem -s 127.0.0.1 -p 8085 -r estrealm -v
