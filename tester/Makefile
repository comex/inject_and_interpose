GCC = gcc
ARCH = 
ifeq "$(findstring -arch,$(GCC))" ""
ARCH = -arch i386 -arch x86_64 -arch ppc #-arch ppc64
endif

all: testlib tester

testlib: testlib.c Makefile
	$(GCC) $(ARCH) -dynamiclib -o testlib.dylib testlib.c
tester: tester.c ../*.c ../*.h Makefile
	$(GCC) -arch i386 -g3 -o tester -I.. tester.c ../*.c ../*.h -Wall -Wno-parentheses
clean:
	rm -f tester testlib.dylib
