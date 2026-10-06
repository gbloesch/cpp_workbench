## C++ Security Workbench

C++ Security Workbench is a VS Code project that performs basic static analysis on C++ code.

The current version focuses on:

SQL injection
Memory leaks
Where each finding appears in the code

The code is analyzed without being executed.

## SQL Injection

The analyzer looks for SQL queries that use user-controlled input.

string concatenation
`+=`
`if` statements
loops
switch cases

SQL findings can also include severity and a suggested fix, such as using a parameterized query.

## Memory Leaks

The analyzer also checks for dynamically allocated memory that may not be freed.

Example:

void example() {
    int* number = new int(42);
}


It can detect cases such as:

missing `delete`
allocations inside loops
allocations inside branches
early returns that skip cleanup
conditional cleanup

## Sample Files

Examples are separated by vulnerability type:

examples/
    SQLinjection.cpp
    memory_leak.cpp
    safe.cpp


`SQLinjection.cpp` contains different SQL injection cases.

`memory_leak.cpp` contains different memory leak cases.

`safe.cpp` contains examples that should not be flagged.

## Pattern Analysis

The pattern analyzer records where each finding occurs.

Examples of locations include:

for
while
if
else
case
switch
try
catch
function
global-or-unknown


It also reports counts and percentages for SQL injection and memory leak findings.

## Main Files

native/
    cpp_model.hpp
    security_analyzer.cpp
    pattern_analyzer.cpp

rules/
    security-rules.json

examples/
    sql_injection_examples.cpp
    memory_leak_examples.cpp
    safe.cpp


`security_analyzer.cpp` finds possible security issues.

`pattern_analyzer.cpp` determines where those findings occur.

`cpp_model.hpp` contains the simplified C++ model used by the analyzers.

## Build
Analyzers are written in C++17 and can be compiled with any compatible compiler.

Option 1: use Make
    if make is installed:
    make

Option 2: Compile Manually
    Compile Directly with: 
    g++ -std=c++17 native/security_analyzer.cpp -o bin/win32-x64/security_analyzer.exe
    g++ -std=c++17 native/pattern_analyzer.cpp -o bin/win32-x64/pattern_analyzer.exe

Option 3: Using Node
    node scripts/build.js

To run the VS Code extension:
 1. Open the project in VS Code and press: F5
 2. This opens an extension development window
 3. Open a C++ file, press Ctrl + Shift + P
 4. Run C++ Security: Analyze Currrent File
 5. If issues are found they are highlighted in Problems
 6. If no issues, the extension displays: "C++ Security: Analysis complete! No security issues found."
 7. To view pattern analysis run: C++ Security: View Patterns


## Limitations

This is a prototype static analyzer and does not fully understand every C++ feature.

Some current limitations include:

limited testing examples
macros
advanced pointer behavior
multi-file analysis
complex SQL sanitization

The goal is to detect common security patterns and show the results clearly inside VS Code.