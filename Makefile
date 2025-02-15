CXX = g++
CXXFLAGS = -Wall -g -std=c++17

INCLUDES = -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib
SERVER_LIBS = -lssl -lcrypto
CLIENT_LIBS = -lssl -lcrypto -lncurses -lmpg123 -lportaudio

TARGETS = server client

all: $(TARGETS)

server: server.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LDFLAGS) -o server server.cpp $(SERVER_LIBS)

client: client.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LDFLAGS) -o client client.cpp $(CLIENT_LIBS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
