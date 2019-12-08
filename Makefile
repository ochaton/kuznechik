CC = cc -std=c11 -ggdb -O0
CFLAGS += -Werror -Wignored-qualifiers -Winit-self \
		-Wswitch-default -Wfloat-equal -Wshadow -Wpointer-arith \
		-Wtype-limits -Wempty-body \
		-Wmissing-field-initializers -Wextra \
		-Wno-pointer-to-int-cast -D_BSD_SOURCE

TARGET = kuznechik
# Directories with source code
SRC_DIR = src
INCLUDE_DIR = src
TEST_DIR = tests

BUILD_DIR = build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin

# Add headers dirs to gcc search path
CFLAGS += -I $(INCLUDE_DIR)

# Helper macros
# subst is sensitive to leading spaces in arguments.
make_path = $(addsuffix $(1), $(basename $(subst $(2), $(3), $(4))))
# Takes path list with source files and returns pathes to related objects.
src_to_obj = $(call make_path,.o, $(SRC_DIR), $(OBJ_DIR), $(1))
# Takes path list with object files and returns pathes to related dep. file.

# All source files in our project that must be built into movable object code.
CFILES := $(wildcard $(SRC_DIR)/*.c)
OBJFILES := $(call src_to_obj, $(CFILES))
TESTFILES := $(call src_to_obj, $(wildcard $(TEST_DIR)/*.c))

# Default target (make without specified target).
.DEFAULT_GOAL := all

# Alias to make all targets.
.PHONY: all
all: release

release: CC += -O2
release: CFLAGS += -Werror
release: directories $(BIN_DIR)/$(TARGET)

debug: CC += -DDEBUG -ggdb3
debug: directories $(BIN_DIR)/$(TARGET)

directories:
	mkdir -p $(BUILD_DIR) $(OBJ_DIR) $(BIN_DIR)

# Suppress makefile rebuilding.
Makefile: ;

# Rules for compiling targets
$(BIN_DIR)/$(TARGET): $(OBJFILES) main.o
	$(CC) $(CFLAGS) $(filter %.o, $^) -o $@

# Pattern for compiling object files (*.o)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $(call src_to_obj, $<) $<

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Fictive target
.PHONY: clean
# Delete all temprorary and binary files
clean:
	rm -rf $(BUILD_DIR)

# This section for runing ad testing

# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

run: $(BIN_DIR)/$(TARGET)
	$^ $(RUN_ARGS)

test: directories $(OBJFILES) $(TESTFILES)
	$(CC) $(CFLAGS) $(filter %.o, $^) -o $@

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -c -o $@ $<