# Master Makefile for NetGuard: Kernel-Space Packet Filter & Rule Enforcement Agent

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -I./common -I./agent
LDFLAGS := -pthread
X11_FLAGS := -I/usr/include/freetype2 -lX11 -lXft -lfreetype
TUI_FLAGS := -lncurses

BIN_DIR := bin
AGENT_BIN := $(BIN_DIR)/netguard
GUI_BIN   := $(BIN_DIR)/netguard-gui
TUI_BIN   := $(BIN_DIR)/netguard-tui
TEST_BIN  := $(BIN_DIR)/netguard-tests

COMMON_SRCS := agent/NetlinkClient.cpp agent/RuleManager.cpp agent/Statistics.cpp
AGENT_SRCS  := agent/main.cpp agent/CLI.cpp $(COMMON_SRCS)
GUI_SRCS    := ui/gui_main.cpp ui/NetGuardGUI.cpp ui/X11Canvas.cpp $(COMMON_SRCS)
TUI_SRCS    := ui/tui_main.cpp ui/NetGuardTUI.cpp $(COMMON_SRCS)
TEST_SRCS   := tests/test_main.cpp tests/test_rules.cpp tests/test_parser.cpp tests/test_netlink_proto.cpp $(COMMON_SRCS)

.PHONY: all kernel agent gui tui tests clean test install uninstall help

all: kernel agent gui tui tests
	@echo "============================================================"
	@echo " NetGuard Build Complete! All binaries generated in $(BIN_DIR)/"
	@echo "============================================================"
	@echo " Kernel Module: kernel/netguard_mod.ko"
	@echo " CLI Agent:     $(AGENT_BIN)"
	@echo " GUI Dashboard: $(GUI_BIN)"
	@echo " TUI Dashboard: $(TUI_BIN)"
	@echo " Test Suite:    $(TEST_BIN)"
	@echo "============================================================"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

kernel:
	@echo "=== Building NetGuard Linux Kernel Module ==="
	$(MAKE) -C kernel

agent: $(BIN_DIR)
	@echo "=== Building NetGuard C++ User-Space Agent (CLI) ==="
	$(CXX) $(CXXFLAGS) $(AGENT_SRCS) -o $(AGENT_BIN) $(LDFLAGS)

gui: $(BIN_DIR)
	@echo "=== Building NetGuard C++ Graphical NOC Dashboard ==="
	$(CXX) $(CXXFLAGS) $(GUI_SRCS) -o $(GUI_BIN) $(X11_FLAGS) $(LDFLAGS)

tui: $(BIN_DIR)
	@echo "=== Building NetGuard C++ Terminal NOC Dashboard ==="
	$(CXX) $(CXXFLAGS) $(TUI_SRCS) -o $(TUI_BIN) $(TUI_FLAGS) $(LDFLAGS)

tests: $(BIN_DIR)
	@echo "=== Building NetGuard Unit Test Suite ==="
	$(CXX) $(CXXFLAGS) $(TEST_SRCS) -o $(TEST_BIN) $(LDFLAGS)

test: tests
	@echo "=== Running NetGuard Unit Tests ==="
	./$(TEST_BIN)

clean:
	@echo "=== Cleaning NetGuard Build Artifacts ==="
	$(MAKE) -C kernel clean
	rm -rf $(BIN_DIR)
	rm -f /tmp/netguard_test_rules.csv

install: all
	@echo "=== Installing NetGuard System Components ==="
	sudo ./scripts/install.sh

uninstall:
	@echo "=== Uninstalling NetGuard System Components ==="
	sudo ./scripts/uninstall.sh

help:
	@echo "NetGuard Build System:"
	@echo "  make all       - Build kernel module, CLI, GUI, TUI, and tests"
	@echo "  make kernel    - Build only kernel/netguard_mod.ko"
	@echo "  make agent     - Build only bin/netguard CLI tool"
	@echo "  make gui       - Build only bin/netguard-gui technical NOC dashboard"
	@echo "  make tui       - Build only bin/netguard-tui terminal dashboard"
	@echo "  make test      - Build and execute unit tests"
	@echo "  make clean     - Remove all build artifacts"
	@echo "  make install   - Install binaries and load kernel module"
	@echo "  make uninstall - Unload kernel module and remove installed binaries"
