# Category Matrix

| Pack | จำนวน | จุดประสงค์หลัก | Engine เด่น |
|---|---:|---|---|
| Core Seed | 21 | กฎเดิมที่แก้ false positive และ target | RE2, parser, reputation |
| HTTP Protocol | 45 | request line, header, framing, smuggling, host, cache | parser, policy |
| Input Injection | 75 | SQLi, NoSQLi, XSS, LDAP, XPath, CRLF, CSV, prototype pollution | RE2, parser |
| Server Side | 60 | command, SSTI, XML, deserialization, traversal, SSRF | RE2, DNS policy |
| Files / Upload | 50 | secret files, diagnostics, upload, archive, webshell | RE2, file inspector |
| Identity / API | 65 | auth, session, JWT/OAuth/SAML, OpenAPI, GraphQL, gRPC | stateful, token parser, schema |
| Abuse / Business | 50 | scanner, bot, rate, scraping, checkout, payment, workflow | stateful |
| Platform / Cloud | 60 | CMS/framework/admin console, metadata, containers, DevOps | RE2 |
| Response / Privacy | 40 | stack trace, token leakage, headers, CORS, cache, PDPA | RE2, response policy |
| AI / LLM / Agent | 31 | prompt signals, model quota, RAG, tool, MCP | RE2, schema, agent gateway |
| Threat Intel / VP | 15 | feed, fingerprint, TTL, affected version, canary, approval | reputation, deployment |
| **รวม** | **512** |  |  |

## Coverage roots

```text
protocol
routing
cache
injection
rce
xml
deserialization
traversal
ssrf
exposure
upload
auth
session
token
oauth
api
business
abuse
recon
behavior
platform
cloud
devops
response
privacy
ai
threat-intel
virtual-patch
```

## สถิติ engine

| Engine | Rules |
|---|---:|
| `re2` | 281 |
| `stateful` | 65 |
| `parser` | 47 |
| `policy` | 20 |
| `token_parser` | 20 |
| `file_inspector` | 18 |
| `response_policy` | 15 |
| `schema` | 12 |
| `agent_gateway` | 9 |
| `reputation` | 9 |
| `graphql` | 4 |
| `authorization` | 2 |
| `catalog` | 2 |
| `deployment` | 2 |
| `grpc` | 2 |
| `websocket` | 2 |
| `dns_policy` | 1 |
| `signature` | 1 |

`re2` จำนวน 281 ข้อผ่าน RE2 compile โดยมี 236 ข้อเป็น direct-import subset ของ UI ปัจจุบัน ส่วน engine อื่นคือ contract สำหรับ CherryWAF data plane/control plane
