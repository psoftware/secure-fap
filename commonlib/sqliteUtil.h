#include "commonlib.h"
#include "log.h"
#include <mutex>
#include <sqlite3.h>

extern sqlite3 *database;

bool sqlite_get_user_salt(sqlite3 *db, char *username, char **salt_string);
bool sqlite_check_password(sqlite3 *db, char *username, char *hashed_password);
bool open_database(sqlite3 **db, const char *database_path);
