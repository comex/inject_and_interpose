GCC = gcc
ARCH = 
ifeq "$(findstring -arch,$(GCC))" ""
ARCH = -arch i386 -arch x86_64 -arch ppc #-arch ppc64
endif

all: testlib tester

testlib: testlib.c ../interpose.c ../interpose.h Makefile
	$(GCC) $(ARCH) -dynamiclib -I.. -o testlib.dylib testlib.c ../interpose.c -Wall -Wno-parentheses
tester: tester.c ../inject.c ../inject.h Makefile
	$(GCC) -O3 -g3 -o tester -I.. tester.c ../inject.c -Wall -Wno-parentheses
clean:
	rm -f tester testlib.dylib
