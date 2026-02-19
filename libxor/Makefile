CXX = g++
CXXFLAGS = -fPIC -Wall -O2
LDFLAGS = -shared

TARGET = libxor.so
SRC = xor.cpp

CLI_TARGET = cli
CLI_SRC = cli.cpp 

all: $(TARGET) $(CLI_TARGET)

$(TARGET): $(SRC) xor.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(SRC)

$(CLI_TARGET): $(CLI_SRC)
	$(CXX) -o $@ $(CLI_SRC) -ldl

clean:
	rm -f $(TARGET) $(CLI_TARGET)

.PHONY: all clean
