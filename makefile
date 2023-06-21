LDLIBS=-lpcap

all: wa

wa: mac.o main.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o