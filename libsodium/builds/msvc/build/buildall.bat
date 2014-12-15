@ECHO OFF

CALL buildbase.bat ..\vs2013\libsodium.sln 12
ECHO.
CALL buildbase.bat ..\vs2012\libsodium.sln 11
ECHO.
CALL buildbase.bat ..\vs2010\libsodium.sln 10
ECHO.

PAUSE