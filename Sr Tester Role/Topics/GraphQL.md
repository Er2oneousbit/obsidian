## 🛡️ Interview Notes: What Is GraphQL Testing?

### What is GraphQL?
- **GraphQL** is an API query language and runtime for APIs.  
- Unlike REST (multiple endpoints), GraphQL typically exposes **one endpoint** (`/graphql`) that clients query with flexible requests.  
- Clients can request **exact fields they need**, but if not secured, attackers can:  
  - Pull excessive data  
  - Abuse nested queries  
  - Manipulate authorization gaps  

---

### 🧪 How to Test GraphQL APIs

#### 🔍 Recon
- Look for `/graphql`, `/graphiql`, `/playground` endpoints.  
- Check if **introspection** is enabled → reveals full schema (types, queries, mutations).  
- Use tools: **Burp**, **GraphQLmap**, **InQL**, **Altair**.  

#### 💥 Common Vulnerabilities
- **Excessive Data Exposure**  
  - Query more fields than intended.  
  - Example: request hidden fields like `passwordHash` or `isAdmin`.  

- **Broken Access Control**  
  - Query/mutate objects you don’t own.  
  - Example: changing `userID` in a mutation → classic **BOLA**.  

- **Denial of Service (DoS)**  
  - Deeply nested queries (a.k.a. “GraphQL recursion bombs”).  
  - Example: `{user {friends {friends {friends {...}}}}}`  

- **Injection Attacks**  
  - If GraphQL resolvers use unsafe DB queries → still vulnerable to **SQLi/NoSQLi**.  

- **Introspection Exposure**  
  - Schema reveals internal logic → helps attackers map API quickly.  

#### 🔧 Example Queries (defanged)
- Data exposure attempt:
  ```graphql
  {
    users {
      id
      email
      passwordHash
    }
  }
  ```
- Nested query DoS attempt:
```graphql
  user(id:1) {
    friends {
      friends {
        friends {
          name
        }
      }
    }
  }
}
```

### 🛡️ How to Fix GraphQL Issues
- Disable **introspection** in production (or restrict by role)
- Implement **strict authorization** at field and object level
- Enforce **query complexity limits** (depth limiting, cost analysis)
- Use **allow-lists** for safe queries in production
- Sanitize all user inputs (GraphQL doesn’t prevent SQLi/NoSQLi by itself)
- Paginate responses to prevent data scraping

---

### 💡 Interview Tip
- If asked “How is GraphQL different from REST/SOAP?” → emphasize:  
  - **GraphQL** = single endpoint, flexible queries, introspection risk  
  - **REST** = multiple endpoints, predictable structure, common web vulns  
  - **SOAP** = rigid XML/WSDL contracts, legacy-heavy  
