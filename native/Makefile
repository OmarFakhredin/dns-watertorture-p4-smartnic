                                                                                          
CXX ?= g++
CXXFLAGS ?= -O3 -std=c++17 -Wall -Wextra
PKG_CONFIG ?= pkg-config
BUILD ?= ../build
.PHONY: all check dpdk
all: $(BUILD)/policy_fixture $(BUILD)/event_replay
$(BUILD):
	mkdir -p $(BUILD)
$(BUILD)/policy_fixture: core.cpp core.hpp ../tests/native/surplus128_policy_fixture.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -I. core.cpp ../tests/native/surplus128_policy_fixture.cpp -o $@
$(BUILD)/event_replay: core.cpp core.hpp event_replay.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -DORIGINAL_SOURCE core.cpp event_replay.cpp -o $@
check: $(BUILD)/policy_fixture
	$(BUILD)/policy_fixture
dpdk: $(BUILD)/dns_dpdk
$(BUILD)/dns_dpdk: core.cpp core.hpp dpdk_service.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) core.cpp dpdk_service.cpp $$($(PKG_CONFIG) --cflags --libs libdpdk) -o $@
