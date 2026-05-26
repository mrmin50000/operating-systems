CXX = g++
CXXFLAGS = -fPIC -Wall -O2
LDFLAGS = -shared -lpthread

TARGET = libxor.so
SRC = xor.cpp

SECURE_COPY_TARGET = secure_copy
SECURE_COPY_SRC = secure_copy.cpp 

all: $(TARGET) $(SECURE_COPY_TARGET)

$(TARGET): $(SRC) xor.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(SRC)

$(SECURE_COPY_TARGET): $(SECURE_COPY_SRC) $(TARGET)
	$(CXX) -o $@ $(SECURE_COPY_SRC) -pthread -ldl
clean:
	rm -f $(TARGET) $(SECURE_COPY_TARGET)

debug: CXXFLAGS += -DDEBUG_KEY
debug: clean all

probe: CXXFLAGS += -DDEBUG_KEY
probe: clean libxor.so
	$(CXX) -o probe probe.cpp -ldl

.PHONY: all clean debug probe
