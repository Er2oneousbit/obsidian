# mongodump

**Tags:** #MongoDB #database #nosql #exfiltration #dump

Part of the **MongoDB Database Tools** package. Dumps an entire MongoDB database (or a single collection) to BSON on disk — the clean, complete way to exfiltrate a whole instance, versus iterating collections with `find()` in [[Tools/Database/mongosh|mongosh]]. Against an unauthenticated instance it needs no credentials; `mongorestore` reverses it.

**Source:** https://www.mongodb.com/docs/database-tools/mongodump/
**Install:** `apt install mongodb-database-tools`

```bash
# Dump everything from an open instance to ./dump/
mongodump --uri="mongodb://<target>:27017" -o ./dump/
# Authenticated
mongodump --uri="mongodb://<user>:<pass>@<target>:27017/?authSource=admin" -o ./dump/
# One database / collection
mongodump --host <target> --db <db> --collection <coll> -o ./dump/
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Database Services/MongoDB|MongoDB]] — bulk data exfiltration.
> Related tooling: [[Tools/Database/mongosh|mongosh]] (interactive queries), [[Tools/Database/NoSQLMap|NoSQLMap]] (injection/automation).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
