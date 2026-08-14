# Roadmap

## v0.1.0

- 512 categorized rules
- 281 RE2 expressions และ 236 current-UI direct-import rules
- schema, profiles, compiler, RE2 lint และ fixtures
- seed rule corrections
- Thai architecture and integration documentation

## v0.2

- native target registry
- transformation capability matrix
- multipart filename and magic-byte targets
- response phase
- per-route scope and exclusion model
- replay runner against sanitized HAR/JSONL traffic

## v0.3

- distributed rate/sequence engine
- canonical client identity and trusted proxy chain
- JWT/OAuth/SAML verifier
- OpenAPI/JSON Schema enforcement
- GraphQL AST cost engine

## v0.4

- threat-intelligence feed ingestion with STIX/TAXII mapping
- indicator TTL and confidence
- application inventory/version binding
- virtual-patch templates and canary automation

## v0.5

- file inspector, archive limits, AV/YARA
- response DLP and structured redaction
- Thai national ID checksum detector
- secret scanning with context-aware suppression

## v0.6

- AI/LLM endpoint registry
- tokenizer-aware quota
- RAG tenant/provenance binding
- agent tool schema, approval and MCP policy
- prompt-injection risk correlation

## ต่อเนื่อง

CVE-specific virtual patch ไม่ควรเป็นกอง regex ถาวร ต้องผูก product/version, มีวันหมดอายุ, test, telemetry และถอดออกเมื่อ upstream patch ถูกติดตั้ง
