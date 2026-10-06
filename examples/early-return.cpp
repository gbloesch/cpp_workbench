void earlyReturn(bool error) {
    int* number = new int(42);
    if (error) return; // Related location: this path skips delete.
    delete number;
}
// The memory finding is grouped by its ALLOCATION site (function body).
// The report also records the related return location inside the if branch.
