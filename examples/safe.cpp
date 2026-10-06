#include <memory>

void manualCleanup() {
    int* value = new int(5);
    delete value;
}

void automaticCleanup(bool earlyReturn) {
    auto value = std::make_unique<int>(5);
    if (earlyReturn) return;
}

struct MYSQL {};
int mysql_query(MYSQL*, const char*);
void constantQuery(MYSQL* db) {
    mysql_query(db, "SELECT id FROM users");
}
