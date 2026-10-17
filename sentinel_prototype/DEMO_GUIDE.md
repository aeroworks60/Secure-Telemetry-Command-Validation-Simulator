# Sentinel demo guide (2–3 minutes)

## Before presenting

- Start the app with `run_sentinel.bat`.
- Open `http://127.0.0.1:8765` if the browser does not open automatically.
- Avoid running two demo batches unless you intend to clear the previous in-memory results.

## Demo sequence

1. **Overview:** Click `Run 8-message scenario`. Point out the accepted/rejected totals and show that each row includes a reason. The seeded scenario should give **2 accepted and 6 rejected**.
2. **Message Lab:** Select `Valid telemetry` and click `Validate message`. Explain the first acceptance as a synthetic message whose configured checks pass.
3. Submit the exact same JSON again. Explain that the reused ID is rejected. This is duplicate-ID detection within the running process, not complete replay protection.
4. Change `message_id` to a new unique value and set `payload.battery_pct` to `140`. The message should be rejected for the configured 0–100 range.
5. **Rules:** Explain the required schema, timestamp freshness, sequence ordering, role allowlist and that the numerical limits are illustrative demo rules.
6. **Audit Trail:** Show the recorded decisions and optionally export JSON or CSV.

## Suggested explanation

“Sentinel is a local-only educational simulator. It receives fictional JSON telemetry and command messages, applies explicit validation rules, and records an accept/reject decision with a reason. It demonstrates defensive input validation, freshness and duplicate checks, simple role-based command policy, and auditability. It does not send commands to a real satellite. Messages can also carry an HMAC-SHA256 tag so tampered, unsigned and wrong-key messages are rejected. HMAC authenticates; it does not encrypt, and this is a prototype, not a production-secure system.”

## If a judge asks about limitations

- The audit is process-memory only; restarting the app clears it.
- Duplicate message IDs and sequence checks are useful controls but do not authenticate the sender or guarantee complete replay protection.
- HMAC uses one shared key: anyone with the key can sign, and the demo uses a development-only key unless `SENTINEL_HMAC_KEY` is set. It does not encrypt messages and there is no key rotation or per-sender key.
- A valid tag does not prove the message is authorized, fresh or non-replayed; those are separate checks.
- The ranges and roles are synthetic policy decisions for demonstration.


## Orbit view (15 seconds)

On **Overview**, point at the Earth scene after running a scenario: “Each packet is one real validation result. Green packets passed the gate and reach the satellite; red packets are blocked at the gate. If nothing was accepted, the satellite shows nothing received.” It is a stylized simulation, not a real satellite link.

## Authentication demo (about 1 minute)

1. **Overview:** click **Run authentication demo (7 messages)**. Authentication becomes required. Expected: **2 accepted, 5 rejected** (tampered, unsigned, wrong key, malformed tag, and an authentic message from a role that is not authorized).
2. Point at the **AUTH** column: `VALID`, `TAG MISMATCH`, `MISSING TAG`, `MALFORMED TAG`. The last row is authentic (`VALID`) but still rejected by the separate authorization rule.
3. **Message Lab:** load `HMAC: signed valid telemetry` and validate (accepted). Load `HMAC: tampered after signing` and validate (rejected, tag mismatch). Say: “One changed number invalidates the tag, and the key never reaches the browser.”

## Customizing a message (important)

The Message Lab has two ways to customize the input:

1. **Visual builder:** edit Message ID, Satellite ID, timestamp, sequence number, message type, sender role, and the relevant telemetry/command payload fields. Click **Apply fields to JSON**; inspect the generated JSON below; then click **Validate message**.
2. **Raw JSON editor:** click directly in the large `message.json` text area and edit any value. You can add or remove fields to test missing-field, unexpected-field, wrong-type, or malformed-JSON handling. Manual edits are preserved when you click **Validate message**.

If you choose a seeded example from the dropdown, the raw JSON and visual builder are refreshed from that example. If the JSON is manually edited, click **Load current JSON into fields** to populate the visual builder with known fields. Note that applying the visual builder constructs a standard message and does not preserve extra custom keys; use the raw editor for unusual or deliberately invalid structures.
