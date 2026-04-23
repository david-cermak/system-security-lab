CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wno-unused-function -O0 -g

all: mqtt_pub mqtt_sub

mqtt_pub: mqtt_client.cpp
	$(CXX) $(CXXFLAGS) -DBINARY_MODE=1 -o $@ $<

mqtt_sub: mqtt_client.cpp
	$(CXX) $(CXXFLAGS) -DBINARY_MODE=0 -o $@ $<

clean:
	rm -f mqtt_pub mqtt_sub

.PHONY: all clean
