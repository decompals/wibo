all: wibo

CXXFLAGS = -Wall -g -m32 -std=c++17 -lstdc++ -MD
LDFLAGS = -lstdc++fs

BUILD_DIR := build
CPP_FILES := $(wildcard *.cpp)
O_FILES := $(foreach file,$(CPP_FILES),$(BUILD_DIR)/$(file:.cpp=.o))
DEP_FILES := $(O_FILES:.o=.d)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) -c $(CXXFLAGS) $< -o $@

wibo: $(O_FILES)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	$(RM) -r $(BUILD_DIR) wibo

.PHONY: all clean

MAKEFLAGS += --no-builtin-rules

-include $(DEP_FILES)
