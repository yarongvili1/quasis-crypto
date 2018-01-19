@ECHO OFF
@SETLOCAL ENABLEDELAYEDEXPANSION
@SET VSCMD_START_DIR=%CD%

SET PACKAGE=index
SET VERSION=0.1.0
SET MODULES=/I e:\resource

IF NOT EXIST ".\.build" MKDIR ".\.build"

FOR %%m IN (x64) DO (

    SET MACHINE=%%m
    CALL %MSBUILD%\VC\Auxiliary\Build\vcvarsall.bat !MACHINE!

    FOR %%v IN (release) DO (

        SET VARIANT=%%v
        CALL :!VARIANT!

        SET PROGRAM=.\.build\!PACKAGE!-!MACHINE!!VARIANT!
        IF EXIST "!PROGRAM!.exe" DEL !PROGRAM!.exe

        CL /EHsc /W4 /std:c++17 !OPTIONS! !MODULES! /Fo:!PROGRAM! !PACKAGE!.cpp /link /MANIFEST:EMBED /DEBUG:FASTLINK /IGNORE:4099 /OUT:!PROGRAM!.exe

        IF EXIST "!PROGRAM!.exe" !PROGRAM!.exe
    )
)

:debug
    SET VARIANT=d
    SET OPTIONS=/MTd /Ox /Z7 /D:NDEBUG
    GOTO :EOF

:release
    SET VARIANT=
    SET OPTIONS=/MT /Ox /Gw
    GOTO :EOF

:EOF
