# สถาปัตยกรรม CherryRule

## 1. เป้าหมาย

CherryRule เป็น catalog กลาง ไม่ใช่ WAF engine ตัวเดียว กฎแต่ละข้อประกาศว่า engine capability ใดต้องรับผิดชอบ เพื่อหยุดพฤติกรรมยอดนิยมของมนุษย์ที่เอาทุกอย่างยัดลง regex แล้วเรียกว่าสถาปัตยกรรม

```text
Connection / TLS
      │
      ▼
Canonical Client Identity
      │
      ▼
HTTP Protocol Parser
      │
      ├── malformed framing / smuggling → immediate reject
      │
      ▼
Canonicalization Pipeline
      │
      ├── URL decode with depth limit
      ├── Unicode normalization
      ├── path normalization
      ├── query/form/JSON/XML/multipart parsing
      └── named-header extraction
      │
      ▼
Positive Security
      │
      ├── host / route / method
      ├── OpenAPI / JSON Schema
      ├── content type / body size
      └── authorization / tenant binding
      │
      ▼
RE2 Inspection + OWASP CRS
      │
      ▼
Stateful Correlation / Bot / Rate / Business Abuse
      │
      ▼
Application Origin
      │
      ▼
Response Inspection / Header Policy / DLP
```

## 2. Phase

| Phase | ข้อมูล | ตัวอย่าง |
|---|---|---|
| `connection` | source IP, TLS, proxy chain | reputation, JA4, temporary ban |
| `request_headers` | request line, host, headers | smuggling, method, JWT |
| `request_uri` | normalized path/query | sensitive files, platform probes |
| `request_body` | parsed form/JSON/XML/multipart | injection, upload, API schema |
| `response_headers` | status/header/cookie | CORS, HSTS, cache policy |
| `response_body` | bounded text body | stack trace, secret, PII |

Engine ต้องไม่ทำ inspection ก่อน parser จบในจุดที่ framing ยังคลุมเครือ เพราะ front proxy กับ backend อาจเห็นคนละ request และผู้โจมตีก็ไม่ได้เกรงใจ diagram ของเรา

## 3. Target model

Target เป็น logical field ไม่ผูกกับโครงสร้างภายในของ implementation:

```text
request.method
request.raw_line
request.raw_headers
request.host
request.path
request.query
request.body
request.body.json
request.cookies
upload.filename
upload.content_type
upload.bytes
token.parsed
identity.account
tenant.id
response.headers
response.body
```

Visual Rule Studio ต้องมี target mapper จาก logical target ไปยังชื่อปัจจุบัน เช่น:

```text
request.path   → path
request.query  → query
request.body   → body
request.headers → headers
request.cookies → cookies
client.ip      → source_ip
```

## 4. Engine classes

### `re2`

ใช้กับ pattern ที่ deterministic และ bounded ไม่มี lookaround, backreference หรือ recursion ทุก pattern ถูก compile ด้วย Go `regexp` ใน CI ซึ่งใช้ RE2 semantics

### `parser`

ใช้กับสิ่งที่ regex ไม่ควรรับผิดชอบ เช่น:

- duplicate header
- TE/CL conflict
- malformed chunk framing
- invalid percent encoding
- duplicate JSON key
- URL authority
- XML entity limits

### `schema`

OpenAPI, JSON Schema, protobuf และ field allowlist

### `stateful`

rate, quota, sequence, cardinality, replay, behavior cluster และ business workflow ต้องใช้ distributed state store

### `file_inspector`

multipart filename, MIME, magic bytes, archive traversal, macro, AV/YARA และ expansion ratio

### `token_parser`

JWT/OAuth/OIDC/SAML ต้อง parse, verify signature และ validate claim semantics ห้ามตัด token เป็นข้อความแล้วหา keyword แบบพิธีกรรม

### `response_policy`

response header enforcement, bounded body inspection, structured redaction และ DLP

### `reputation` / `dns_policy`

indicator feed, TTL, canonical client IP, DNS resolution, redirect re-check และ egress class

### `agent_gateway`

tool allowlist, argument schema, context binding, human approval, filesystem sandbox และ MCP capability policy

## 5. Transformation pipeline

ลำดับ transform ต้องกำหนดและมีเพดาน:

```text
raw capture
→ validate framing
→ percent decode (bounded depth)
→ HTML entity decode
→ Unicode NFKC where policy allows
→ remove NUL / reject invalid code points
→ path separator normalization
→ dot-segment normalization
→ parse media type
→ parse form / JSON / XML / multipart
→ inspect raw and canonical views
```

ข้อควรระวัง:

- ห้าม decode ไม่จำกัดรอบ เพราะทำให้ CPU amplification
- ห้าม lowercase token, base64, case-sensitive path หรือ signed payload แบบเหมาเข่ง
- เก็บทั้ง raw และ canonical evidence
- signature verification ต้องใช้ raw bytes ตาม provider contract

## 6. Score model

แยก score ตามแหล่ง:

```text
native_score
crs_anomaly_score
behavior_score
reputation_score
response_score
```

ตัวอย่าง decision:

```text
immediate protocol violation      → block
high-confidence secret exposure   → block
native + CRS >= threshold         → block
behavior >= challenge threshold   → challenge
reputation high + anomaly present → block
response secret match             → redact or fail-safe response
```

ห้ามนำ severity มาใส่คอลัมน์ Status อีกครั้ง `critical` คือ severity ส่วน status ต้องเป็น `draft`, `detect`, `canary`, `enabled`, `disabled`, `deprecated`

## 7. Application profile

ทุก application ต้องประกาศอย่างน้อย:

```yaml
technology:
  - go
  - react
routes:
  source: openapi.yaml
trusted_proxies:
  - 10.10.0.0/16
uploads:
  default_extensions: [jpg, png, pdf]
identity:
  account_key: jwt.sub
  tenant_key: jwt.tenant_id
```

จากนั้น profile overlay จึงเปลี่ยน action ของ platform probe ได้อย่างถูกต้อง

## 8. Performance

- regex ต้อง bounded และ compile ล่วงหน้า
- parser rule ควรทำงานครั้งเดียวแล้วแชร์ parsed representation
- body inspection มี route-specific size cap
- response body inspection จำกัดเฉพาะ text types และจำนวน byte
- archive/AV scan แยก queue หรือ stream พร้อม timeout
- stateful key ต้องมี TTL และ cardinality guard
- rule metrics ต้องมี latency percentile, match rate และ false-positive disposition

## 9. Audit evidence

เมื่อ rule match ต้องเก็บ:

```text
rule_id
rule_version
pack_version
application_id
tenant_id
phase
target
matched_offset / parsed field
redacted evidence
raw request hash
canonical request hash
score components
action
exclusion applied
deployment stage
```

ไม่ควรเก็บ secret หรือ body ทั้งก้อนลง audit log แล้วสร้าง data breach รุ่นผู้ดูแลระบบเอง
