CC = arm-none-eabi-gcc
CFLAGS = -Wall -Wextra -g -I./include -I../config -mcpu=cortex-m0 -mthumb -ffunction-sections -fdata-sections
LDFLAGS = -nostdlib -nostartfiles -Wl,--gc-sections -T linker.ld

# Windows commands
RM = del /Q /F
RMDIR = rmdir /S /Q
MKDIR = mkdir

# Source directories
IDE_DIR = ide
INCLUDE_DIR = include
CONFIG_DIR = ../config
SRC_DIR = src

# Source files
IDE_SOURCES = $(IDE_DIR)/ghost_ide.c \
              $(IDE_DIR)/malware_templates.c \
              $(SRC_DIR)/ghost_security.c \
              $(SRC_DIR)/ghost_init.c

SOURCES = lexer.c $(IDE_SOURCES)
OBJECTS = $(SOURCES:.c=.o)
TARGET = ghostc.exe

.PHONY: all clean ide debug flash

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "Linking $@..."
	@$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	@echo "Build complete: $@"
	@arm-none-eabi-size $@

%.o: %.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning..."
	@if exist "$(OBJECTS)" $(RM) $(OBJECTS)
	@if exist "$(TARGET)" $(RM) $(TARGET)
	@if exist "$(OBJECTS:.o=.d)" $(RM) $(OBJECTS:.o=.d)
	@if exist "build" $(RMDIR) build
	@echo "Clean complete"

# IDE component build
ide: CFLAGS += -DIDE_BUILD
ide: $(IDE_SOURCES:.c=.o)
	@echo "Building IDE components..."
	@if not exist "build" $(MKDIR) build
	@$(CC) $(IDE_SOURCES:.c=.o) $(LDFLAGS) -o build/ghost_ide.exe
	@echo "IDE build complete"

# Debug build with symbols
debug: CFLAGS += -DDEBUG -O0 -g3
debug: clean all

# Dependency tracking
-include $(SOURCES:.c=.d)

%.d: %.c
	@$(CC) -MM $(CFLAGS) $< > $@.$$$$
	@sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@
	@$(RM) $@.$$$$

# Help target
help:
	@echo "Available targets:"
	@echo "  all    : Build everything (default)"
	@echo "  ide    : Build IDE components only"
	@echo "  debug  : Build with debug symbols"
	@echo "  clean  : Remove build artifacts"
	@echo "  help   : Show this help message"
