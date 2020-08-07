# set non-optional compiler flags here
CXXFLAGS += -march=native -std=c++11 -Wall -Wextra -pedantic-errors

# set non-optional preprocessor flags here
# eg. project specific include directories
CPPFLAGS += -I ./include -lpthread

# find cpp files in subdirectories
SOURCES := $(shell find . -name '*.cpp')

# find headers
HEADERS := $(shell find . -name '*.h')

OUTPUT := aes-brute-force

# Everything depends on the output
all: $(OUTPUT)

test: $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $(OUTPUT) $(SOUECES)

# The output depends on sources and headers
$(OUTPUT): $(SOURCES) $(HEADERS)
	$(CXX) -Ofast $(CXXFLAGS) $(CPPFLAGS) -o $(OUTPUT)-fast $(SOURCES)
	$(CXX) -g -pg -fno-omit-frame-pointer $(CXXFLAGS) $(CPPFLAGS) -o $(OUTPUT)-test $(SOURCES)

clean:
	$(RM) $(OUTPUT)
