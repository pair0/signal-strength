LDLIBS=-lpcap

all: signal-strength


main.o: mac.h main.h main.cpp

mac.o : mac.h mac.cpp

signal-strength: main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f signal-strength *.o