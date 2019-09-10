CPPFLAGS=-D_GNU_SOURCE
CFLAGS=-std=c99 -Wall -Wextra `pkg-config --cflags libunwind-ptrace libseccomp`
LDLIBS=`pkg-config --libs libunwind-ptrace libseccomp`

aligntrace:
