## 🛡️ Interview Notes: What Are Race Condition Vulnerabilities?

### ❓ What Are Race Conditions?
- A **Race Condition** occurs when two or more operations happen **concurrently**, and the system’s outcome depends on the order/timing of those operations.  
- In web apps, this can let attackers exploit flaws in **transaction handling** or **state validation**.  
- Potential impacts:  
  - 💸 Double-spending (financial fraud)  
  - 🔄 Re-using tokens or one-time links (password reset, coupons)  
  - 📦 Stock depletion or overselling  
  - 🚪 Privilege escalation by bypassing order of operations  

---

### 🧪 How to Detect and Exploit Race Conditions
- Identify **state-changing actions**:  
  - Payments, coupon redemption, account upgrades, password resets  

- Attack strategies:  
  - 🔁 **Replay requests** simultaneously with tools like Burp Intruder (Cluster Bomb mode), Turbo Intruder, or custom scripts  
  - ⚡ Send high-volume parallel requests to see if duplicate actions succeed  
  - 📊 Look for inconsistencies (multiple confirmations, duplicate entries, mismatched balances)  

- Example scenarios (defanged):  
  - Submitting two `POST /transfer` requests at the same time → money sent twice  
  - Sending multiple `POST /redeemCoupon?code=DISCOUNT50` → same coupon applied repeatedly  
  - Concurrent password reset submissions → takeover of victim’s account  

- Indicators of a vulnerable system:  
  - Lack of atomic database operations (no transactions/locking)  
  - No replay protections (e.g., unique nonce per request)  
  - Inconsistent responses under concurrency testing  

---

### 🛡️ How to Fix Race Conditions
- ✅ Use **atomic operations** in the database (transactions, row locking)  
- ✅ Enforce **idempotency** on sensitive actions (same request = same result)  
- ✅ Apply **one-time tokens / nonces** to prevent replay  
- ✅ Add **rate limiting** and request throttling for critical endpoints  
- ✅ Perform security testing under load to detect concurrency issues  
- ✅ Monitor logs for anomalies (e.g., duplicate payments, excessive requests)  

---
