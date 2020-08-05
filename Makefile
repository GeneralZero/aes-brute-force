# set non-optional compiler flags here
CXXFLAGS += -march=native -std=c++11 -Wall -Wextra -pedantic-errors -g

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

# The output depends on sources and headers
$(OUTPUT): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $(OUTPUT) $(SOURCES)

clean:
	$(RM) $(OUTPUT)