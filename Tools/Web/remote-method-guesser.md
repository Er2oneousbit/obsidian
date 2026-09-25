# remote-method-guesser

**Tags:** `#rmg` `#rmi` `#jmx` `#java` `#deserialization` `#rce`

Java RMI vulnerability scanner and attack tool (qtc-de), invoked as `rmg`. It enumerates an RMI registry (bound objects, exposed remote methods), guesses remote method signatures when the interface is unknown, and launches deserialization attacks against RMI endpoints (including the RMI internals: registry, DGC, activation system). Frequently the first tool against port 1099 to decide whether JMX/RMI is exploitable, then paired with [[Tools/Payloads & Shells/ysoserial|ysoserial]] gadget chains.

**Source:** https://github.com/qtc-de/remote-method-guesser
**Install:** Download the release jar or build with Maven; run `java -jar rmg.jar` (or the `rmg` wrapper).

```bash
# Enumerate the RMI registry + known RMI vulnerabilities
rmg enum <target> 1099

# Guess remote method signatures of a bound object
rmg guess <target> 1099

# Deserialization attack against a discovered method
rmg serial <target> 1099 CommonsCollections6 "id" --bound-name <name>
```

JMX-specific companion: [[Tools/Web/beanshooter|beanshooter]].

---

> [!note] **See also** — [[Services/Web Services/JMX|JMX]] — RMI-layer enumeration and deserialization against the JMX/RMI registry.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
