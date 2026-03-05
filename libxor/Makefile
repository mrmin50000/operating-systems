CXX = g++
CXXFLAGS = -fPIC -Wall -O2
LDFLAGS = -shared

TARGET = libxor.so
SRC = xor.cpp

SECURE_COPY_TARGET = secure_copy
SECURE_COPY_SRC = secure_copy.cpp 

all: $(TARGET) $(SECURE_COPY_TARGET)

$(TARGET): $(SRC) xor.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(SRC)

$(SECURE_COPY_TARGET): $(SECURE_COPY_SRC)
	$(CXX) -o $@ $(SECURE_COPY_SRC) -pthread -ldl
clean:
	rm -f $(TARGET) $(SECURE_COPY_TARGET)

.PHONY: all clean
