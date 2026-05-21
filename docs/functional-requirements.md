# Functional Requirements

## FR-01 Query Parsing
System shall parse HTTPQL query input into executable request structures.

## FR-02 Request Execution
System shall execute parsed requests against configured runtime policies.

## FR-03 Request Chaining
System shall allow referencing previous responses using `${response:...}` placeholders.

## FR-04 Secret Interpolation
System shall resolve `${secret:...}` references via configured secret providers.

## FR-05 Environment Reference Blocking
System shall reject `${env:...}` placeholders in query input.

## FR-06 Body Method Support
System shall support body methods: raw, json, form, multipart, graphql, xml, text.

## FR-07 Policy Resolution
System shall compute effective policy from configured layers and apply it during execution.

## FR-08 Guardrail Enforcement
System shall enforce runtime security and execution guardrails before outbound requests.

## FR-09 TLS Customization
System shall support custom TLS options including mTLS client credentials and custom CA.

## FR-10 Auditable Outputs
System shall return structured execution results suitable for auditing and debugging.

