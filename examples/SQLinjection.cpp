// This file contains examples of SQL injection vulnerabilities.

#include <string>

struct MYSQL {};
int mysql_query(MYSQL*, const char*);

void sqlExamples(MYSQL* db, const std::string& username, int choice) {

    // Example of direct SQL injection
    std::string loginQuery =
        "SELECT * FROM users WHERE username='" + username + "'";

    mysql_query(db, loginQuery.c_str());


    // Example of SQL injection in an IF statement
    if (!username.empty()) 
    {
        std::string searchQuery =
            "SELECT * FROM users WHERE name='" + username + "'";

        mysql_query(db, searchQuery.c_str());
    }


    // Example of SQL injection inside a switch statement
    switch (choice) {

        case 1: {
            std::string deleteQuery =
                "DELETE FROM users WHERE name='" + username + "'";

            mysql_query(db, deleteQuery.c_str());
            break;
        }

        case 2: {
            std::string updateQuery =
                "UPDATE users SET active=1 WHERE name='" + username + "'";

            mysql_query(db, updateQuery.c_str());
            break;
        }

        default:
            break;
    }


    // Example of query built over multiple lines
    std::string builtQuery =
        "SELECT * FROM users WHERE username='";

    builtQuery += username;
    builtQuery += "'";

    mysql_query(db, builtQuery.c_str());


    // Example of SQL injection directly in mysql_query
    mysql_query(
        db,
        ("DELETE FROM users WHERE username='" + username + "'").c_str()
    );


    // Example of safe SQL query
    // This should NOT be reported as SQL injection
    std::string safeQuery =
        "SELECT * FROM users WHERE active=1";

    mysql_query(db, safeQuery.c_str());
}