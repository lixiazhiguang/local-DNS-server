CXX = g++ -std=c++11
OBJ = main.o DNS.o cache.o blacklist.o log.o

all: dnsrelay

dnsrelay: $(OBJ)
	$(CXX) $(OBJ) -o dnsrelay

main.o: main.cpp DNS.h cache.h blacklist.h log.h
	$(CXX) -c main.cpp

DNS.o: DNS.cpp DNS.h cache.h log.h
	$(CXX) -c DNS.cpp

cache.o: cache.cpp cache.h blacklist.h log.h
	$(CXX) -c cache.cpp

blacklist.o: blacklist.cpp blacklist.h log.h
	$(CXX) -c blacklist.cpp

log.o: log.cpp log.h
	$(CXX) -c log.cpp

clean:
	rm *.o
