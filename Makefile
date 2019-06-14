CFLAGS=-std=c99 -Wall -Wextra -ggdb `pkg-config --cflags libunwind-ptrace libseccomp`
LDLIBS=`pkg-config --libs libunwind-ptrace libseccomp`

aligntrace:
