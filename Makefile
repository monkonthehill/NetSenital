# ==============================================================================
# NetSentinel - High-Performance AI-Powered Network Intrusion Detection System
# Repository: https://github.com/monkonthehill/NetSenital
# ==============================================================================

CXX      := g++
CXXFLAGS := -O2 -Wall -Wextra -Wshadow -std=c++17 -pthread
LDFLAGS  := -lpcap

SRC_DIR  := src
INC_DIR  := include
TEST_DIR := tests

SRCS     := $(SRC_DIR)/main.cpp $(SRC_DIR)/sniffer.cpp $(SRC_DIR)/parser.cpp $(SRC_DIR)/flow.cpp $(SRC_DIR)/extractor.cpp
TEST_SRC := $(SRC_DIR)/flow.cpp $(SRC_DIR)/extractor.cpp $(TEST_DIR)/test_flows.cpp

TARGET   := netsentinel
TEST_BIN := run_tests

PYTHON   := python3
PIP      := pip3

# Default interface for CLI capture
IFACE    ?= lo

.PHONY: all build test install-deps setup run dashboard cli train clean help

all: build

build: $(TARGET)

$(TARGET): $(SRCS)
	@echo "==> Compiling NetSentinel core C++ engine..."
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	@echo "==> Successfully built $(TARGET)"

test: $(TEST_BIN)
	@echo "==> Running NetSentinel test suite..."
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC)
	@echo "==> Compiling test suite..."
	$(CXX) $(CXXFLAGS) $(TEST_SRC) -o $(TEST_BIN) $(LDFLAGS)

install-deps:
	@echo "==> Detecting Linux package manager and installing dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "Found apt-get (Debian/Ubuntu)..."; \
		sudo apt-get update && sudo apt-get install -y build-essential g++ libpcap-dev python3 python3-pip python3-venv; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "Found dnf (Fedora/RHEL)..."; \
		sudo dnf install -y gcc-c++ make libpcap-devel python3 python3-pip; \
	elif command -v pacman >/dev/null 2>&1; then \
		echo "Found pacman (Arch Linux)..."; \
		sudo pacman -Sy --noconfirm base-devel gcc make libpcap python python-pip; \
	elif command -v zypper >/dev/null 2>&1; then \
		echo "Found zypper (openSUSE)..."; \
		sudo zypper install -y gcc-c++ make libpcap-devel python3 python3-pip; \
	else \
		echo "Warning: Could not detect known package manager. Please ensure g++, libpcap-dev, and python3-pip are installed."; \
	fi
	@echo "==> Installing Python requirements..."
	$(PIP) install -r requirements.txt --break-system-packages 2>/dev/null || $(PIP) install -r requirements.txt || true
	@echo "==> Dependencies installation complete!"

setup: install-deps build
	@echo "==> Creating required directories..."
	@mkdir -p Data models
	@echo "==> Attempting to set CAP_NET_RAW capability on $(TARGET)..."
	@-sudo setcap cap_net_raw=ep $(TARGET) 2>/dev/null || true
	@echo "==> Running verification tests..."
	@$(MAKE) test
	@echo ""
	@echo "============================================================"
	@echo " NetSentinel is installed and ready to run!"
	@echo " Start dashboard:   make run"
	@echo " CLI capture:       make cli IFACE=your_interface"
	@echo "============================================================"

run: dashboard

dashboard: build
	@echo "==> Launching NetSentinel Web Command & Control Dashboard..."
	@echo "==> Open your browser at http://localhost:8000"
	sudo $(PYTHON) web_app.py

cli: build
	@echo "==> Launching NetSentinel CLI on interface: $(IFACE)..."
	sudo ./$(TARGET) $(IFACE)

train:
	@echo "==> Training Random Forest & XGBoost ML models..."
	$(PYTHON) scripts/train_model.py

clean:
	@echo "==> Cleaning build artifacts..."
	rm -f $(TARGET) $(TEST_BIN) netsentinal *.o
	rm -rf __pycache__ .pytest_cache
	@echo "==> Clean complete."

help:
	@echo "============================================================"
	@echo " NetSentinel Build & Run Guide"
	@echo " Repository: https://github.com/monkonthehill/NetSenital"
	@echo "============================================================"
	@echo "  make setup        - One-step setup (installs deps, builds & tests)"
	@echo "  make install-deps - Install system and Python dependencies"
	@echo "  make build        - Compile the C++ packet sniffer engine"
	@echo "  make test         - Run AI-generated flow verification tests"
	@echo "  make run          - Launch Web Control Dashboard (port 8000)"
	@echo "  make cli [IFACE=] - Run CLI sniffer on specific interface"
	@echo "  make train        - Train/refresh ML threat detection models"
	@echo "  make clean        - Remove binaries and temporary files"
	@echo "============================================================"
