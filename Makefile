# dns-middleware: GNU Make build.

# Make predefines CXX (as "g++"), so a plain `CXX ?= g++-14` would never take effect.
# This has the same intent: use g++-14 unless CXX is set in the environment or on the
# command line (e.g. `make CXX=clang++`).
ifeq ($(origin CXX),default)
  CXX := g++-14
endif

CLANG_FORMAT ?= clang-format

BUILD_DIR      ?= build
EXTRA_CXXFLAGS ?=

CPPFLAGS := -Iinclude -MMD -MP
CXXFLAGS := -std=c++23 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -g $(EXTRA_CXXFLAGS)
TEST_LIBS := -lgtest_main -lgtest -pthread

# Command prefix used to launch the test binary (set by the tsan target).
TEST_RUNNER ?=

SRCS      := $(wildcard src/*.cpp)
TEST_SRCS := $(wildcard tests/*.cpp)
TOOL_SRCS := tools/load_gen.cpp

LIB_OBJS  := $(SRCS:%.cpp=$(BUILD_DIR)/%.o)
TEST_OBJS := $(TEST_SRCS:%.cpp=$(BUILD_DIR)/%.o)
TOOL_OBJS := $(TOOL_SRCS:%.cpp=$(BUILD_DIR)/%.o)

LIB       := $(BUILD_DIR)/libmw.a
LOAD_GEN  := $(BUILD_DIR)/load_gen
RUN_TESTS := $(BUILD_DIR)/run_tests

FORMAT_FILES = $(shell find include src tests tools -name '*.hpp' -o -name '*.cpp')

.PHONY: all test asan tsan release format clean

all: $(LIB) $(LOAD_GEN)

test: $(RUN_TESTS)
	$(TEST_RUNNER) ./$(RUN_TESTS)

asan:
	$(MAKE) BUILD_DIR=build/asan \
		EXTRA_CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" all test

# Older TSan runtimes abort with "unexpected memory mapping" on kernels with high ASLR
# entropy (vm.mmap_rnd_bits=32, the default on Linux 6.6+), so tests run with ASLR disabled.
tsan:
	$(MAKE) BUILD_DIR=build/tsan EXTRA_CXXFLAGS="-fsanitize=thread" \
		TEST_RUNNER="setarch $$(uname -m) -R" all test

release:
	$(MAKE) BUILD_DIR=build/release EXTRA_CXXFLAGS="-O2 -DNDEBUG" all

format:
	$(CLANG_FORMAT) -i $(FORMAT_FILES)

clean:
	rm -rf build

$(LIB): $(LIB_OBJS)
	@mkdir -p $(@D)
	rm -f $@
	$(AR) rcs $@ $^

$(LOAD_GEN): $(TOOL_OBJS) $(LIB)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(RUN_TESTS): $(TEST_OBJS) $(LIB)
	$(CXX) $(CXXFLAGS) $^ $(TEST_LIBS) -o $@

$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

-include $(LIB_OBJS:.o=.d) $(TEST_OBJS:.o=.d) $(TOOL_OBJS:.o=.d)
