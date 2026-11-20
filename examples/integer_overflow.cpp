int add(int a, int b) {
    int result = a + b; // Possible overflow
    return result;
}
void overflowExamples() {
    int x = 2147483647;
    x += 1;                 // Possible overflow
    ++x;                    // Possible overflow
    int bad = 2147483647 + 1; // Definite constant overflow
    int safe = 10 + 20;     // No overflow warning
}
