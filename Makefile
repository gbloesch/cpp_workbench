CXX = C:/msys64/ucrt64/bin/g++.exe
CXXFLAGS = -std=c++17 -Wall

BIN = bin/win32-x64

all: $(BIN)/security_analyzer.exe $(BIN)/pattern_analyzer.exe

$(BIN):
	mkdir -p $(BIN)

$(BIN)/security_analyzer.exe: native/security_analyzer.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) native/security_analyzer.cpp -o $(BIN)/security_analyzer.exe

$(BIN)/pattern_analyzer.exe: native/pattern_analyzer.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) native/pattern_analyzer.cpp -o $(BIN)/pattern_analyzer.exe

clean:
	rm -f $(BIN)/security_analyzer.exe $(BIN)/pattern_analyzer.exe