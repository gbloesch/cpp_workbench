#include <cstdlib>
#include <string>

// Declarations only: these examples are analyzed, not linked or executed.
struct MYSQL {};
int mysql_query(MYSQL*, const char*);

void examples(MYSQL* db, const std::string& username, bool error, int choice) {
    for (int i = 0; i < 3; ++i) {
        int* loopAllocation = new int(i); // Possible leak in a FOR loop.
    }

    if (error) {
        int* branchAllocation = new int(42); // Possible leak in an IF branch.
    }

    switch (choice) {
        case 1: {
            std::string query = "SELECT * FROM users WHERE name='" + username + "'";
            mysql_query(db, query.c_str()); // Possible SQL injection in CASE.
            break;
        }
        default:
            break;
    }

    for (int i = 0; i < 2; ++i) {
        mysql_query(db, ("DELETE FROM users WHERE name='" + username + "'").c_str());
    }
}
