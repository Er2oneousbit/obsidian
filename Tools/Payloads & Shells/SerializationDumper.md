# SerializationDumper

**Tags:** #SerializationDumper #Deserialization #Java #Analysis #ReverseEngineering #WebAppAttacks

`SerializationDumper` converts a Java serialization stream into a human-readable tree — class names, field names, field types, and values, one line at a time. Use it to answer the questions that decide whether a deserialization sink is exploitable: *what class is the app actually expecting, what fields does it carry, and did my crafted payload serialize the way I intended?* It also rebuilds a stream from the dumped text, so you can hand-edit a field value and re-serialize.

**Source:** https://github.com/NickstaDB/SerializationDumper
**Install:** `git clone https://github.com/NickstaDB/SerializationDumper && cd SerializationDumper && ./build.sh` (or download the release JAR)

```bash
# Dump a captured stream from hex
java -jar SerializationDumper.jar aced0005737200...

# Dump from a file (e.g. a payload you generated, or a captured POST body)
java -jar SerializationDumper.jar -f payload.ser

# Inspect a base64 cookie — decode first
echo "rO0ABXNyAB..." | base64 -d > cookie.ser
java -jar SerializationDumper.jar -f cookie.ser

# Rebuild a stream after editing the dumped text (round-trip)
java -jar SerializationDumper.jar -r edited.txt -o rebuilt.ser
```

> [!tip] Dump the *legitimate* object the app sends before crafting anything. Knowing the expected class and its fields tells you whether you can get away with simple property manipulation — often enough for auth bypass or privilege escalation — instead of hunting a full RCE gadget chain.

> [!note] Reads the raw stream format, so it works on any `aced 0005` blob regardless of whether the classes are on your classpath — no need to have the target's JARs.

> [!note] **See also** — [[Techniques/Deserialization|Deserialization]] — inspecting and hand-editing Java serialized objects; pairs with [[Tools/Payloads & Shells/ysoserial|ysoserial]] for payload generation.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
