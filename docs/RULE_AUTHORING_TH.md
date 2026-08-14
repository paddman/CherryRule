# คู่มือเขียนกฎ CherryRule

## 1. ID และช่วงหมายเลข

ดูช่วง ID ที่ `metadata/categories.yaml` ห้าม reuse ID แม้กฎจะถูกลบ ให้เปลี่ยน `status: deprecated` เพื่อให้ audit ย้อนกลับได้

## 2. โครงสร้างขั้นต่ำ

```yaml
id: CWAF-INJ-220001
name: UNION SELECT sequence
name_th: ตรวจ UNION SELECT
description_th: ตรวจลำดับ keyword ที่สัมพันธ์กับ SQL injection
category: injection.sql
phase: request_body
engine: re2
targets:
  - request.query
  - request.body
operator:
  type: regex
  pattern: '(?i)\bunion(?:\s+all)?\s+select\b'
transforms:
  - url_decode
  - unicode_normalize
action:
  mode: score
  score: 10
severity: critical
confidence: high
paranoia_level: 1
default_enabled: true
status: experimental
tags: [sqli, cwe-89]
false_positive_notes: ใช้ cumulative score และทำ exclusion ราย parameter
```

## 3. เลือก engine ให้ถูก

ใช้ `re2` เมื่อคำตอบขึ้นกับข้อความภายใน target เดียวอย่างชัดเจน

ใช้ `parser` เมื่อจำเป็นต้องรู้:

- header ซ้ำหรือลำดับ header
- request framing
- object key ซ้ำ
- URL host/port/userinfo
- XML entity structure
- content disposition

ใช้ `stateful` เมื่อจำเป็นต้องเห็นหลาย request หรือหลาย identity

ใช้ `schema` เมื่อมีสัญญา API ที่แน่นอน

ใช้ `policy` เมื่อเป็น allowlist/denylist ตาม application config

## 4. RE2 rule

ห้ามใช้:

```text
lookahead       (?=...)
negative lookahead (?!...)
lookbehind      (?<=...)
backreference   \1
named capture   (?P<name>...)
conditional     (?(id)...)
atomic group    (?>...)
```

แนวทาง performance:

- จำกัด wildcard เช่น `.{0,240}` แทน `.*`
- anchor target เมื่อเป็น path หรือ method
- ไม่ซ้อน quantifier โดยไม่จำเป็น
- ใช้ parser แทน regex สำหรับโครงสร้าง
- ทุก pattern ต้องผ่าน `go run tools/re2lint.go`

## 5. Action

| Action | ใช้เมื่อ |
|---|---|
| `score` | signal เดี่ยวมี false positive ได้ |
| `block` | protocol invalid, exact secret path, exploit primitive ที่มั่นใจสูง |
| `challenge` | bot/credential/recon ที่ยังไม่ควร hard block |
| `throttle` | rate/quota/cost abuse |
| `sanitize` | ลบ untrusted header หรือเติม response header |
| `redact` | response DLP ที่ serializer ทำได้อย่างปลอดภัย |

อย่า block จากคำว่า `select`, `<svg>`, `admin` หรือ `powershell` ตัวเดียวในทุกแอป ระบบเอกสาร, code editor และ security dashboard มีสิทธิ์พูดคำเหล่านี้โดยไม่ใช่อาชญากร

## 6. Severity กับ confidence

Severity คือผลกระทบหากเป็นการโจมตีจริง  
Confidence คือความมั่นใจว่าการ match หมายถึงการโจมตี

ตัวอย่าง:

```text
Private key marker        severity critical / confidence high
Generic SQL keyword       severity high     / confidence low
Protocol TE+CL conflict   severity critical / confidence high
AI jailbreak phrase       severity high     / confidence low-medium
```

## 7. False-positive note

กฎ `score` และกฎที่อิงเทคโนโลยีต้องมีคำแนะนำอย่างน้อยหนึ่งข้อ:

- route ที่ควร exclude
- parameter ที่อาจรับ HTML/code
- application profile ที่เกี่ยวข้อง
- content type ที่ต้องจำกัด
- เหตุผลที่ไม่ควร global block

## 8. Test fixture

ทุก virtual patch ต้องมีอย่างน้อย:

- positive cases 2
- negative cases 3
- encoded variant
- normal business request
- replay traffic result

Fixture กลางอยู่ใน `tests/fixtures/re2.json`

## 9. Review checklist

```text
[ ] ID ไม่ซ้ำ
[ ] category และ phase ถูกต้อง
[ ] target มีอยู่จริง
[ ] RE2 compile ผ่าน
[ ] ไม่มี unsupported construct
[ ] transform ไม่ทำลาย signed/raw payload
[ ] action สมเหตุผลกับ confidence
[ ] มี false-positive note
[ ] มี application scope
[ ] มี positive/negative fixtures
[ ] benchmark latency ผ่าน
[ ] rollback ได้
```
