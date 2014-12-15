REM WORK IN PROGRESS

@ECHO OFF

if "%1" == "" (
    echo "Usage: wintest.bat <DebugDLL | ReleaseDLL | DebugLIB | ReleaseLIB | DebugLTCG | DebugLTCG"
    goto :END
)

if "%2" == "x64" (SET ARCH=x64) else (SET ARCH=Win32)
SET CFLAGS=/nologo /DTEST_SRCDIR=\".\" /I..\..\src\libsodium\include\sodium /I..\..\src\libsodium\include /I..\quirks
SET LDFLAGS=/link /LTCG advapi32.lib ..\..\Build\%1\%ARCH%\libsodium.lib

if not "%3" == "" (
    CD %3
)

if not exist sodium_version.c (
    if not exist sodium_version.c (
        echo "Are you on the right path?" %CD%
        goto :END
    )
)

if "%1" == "DebugDLL"   ( goto :DebugDLL )
if "%1" == "ReleaseDLL" ( goto :ReleaseDLL )

if "%1" == "DebugLIB"   ( goto :DebugLIB )
if "%1" == "ReleaseLIB"   ( goto :ReleaseLIB )

if "%1" == "DebugLTCG"   ( goto :DebugLTCG )
if "%1" == "ReleaseLTCG"   ( goto :ReleaseLTCG )

echo "Invalid build type"
goto :END

:DebugDLL
    SET CFLAGS=%CFLAGS% /GS /MDd /Od
    SET PATH=..\..\Build\%1\%ARCH%;%PATH%
    goto :COMPILE
:ReleaseDLL
    SET CFLAGS=%CFLAGS% /MD /Ox 
    SET PATH=..\..\Build\%1\%ARCH%;%PATH% 
    goto :COMPILE

:DebugLIB
    SET CFLAGS=%CFLAGS% /GS /MTd /Od /DSODIUM_STATIC
    goto :COMPILE
:ReleaseLIB
    SET CFLAGS=%CFLAGS% /MT /Ox /DSODIUM_STATIC
    goto :COMPILE

:DebugLTCG
    SET CFLAGS=%CFLAGS% /LTCG /GS /MTd /Od /DSODIUM_STATIC
    goto :COMPILE
:ReleaseLTCG
    SET CFLAGS=%CFLAGS% /LTCG /MT /Ox /DSODIUM_STATIC
    goto :COMPILE

:COMPILE
echo Running the test suite:
FOR %%f in (*.c) DO (
    cl %CFLAGS% %%f %LDFLAGS% /errorReport:prompt /OUT:%%f.exe > NUL 2>&1
    if not exist %%f.exe (
        echo %%f compile failed
        goto :END
    )
    %%f.exe
    if errorlevel 1 ( 
        echo %%f failed
    ) else (
        echo %%f ok
    )
)
REM Remove temporary files
del *.exe *.obj *.res *.exp *.pdb

:END
