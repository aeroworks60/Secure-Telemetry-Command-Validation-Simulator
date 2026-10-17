(() => {
  const exampleSelect = document.getElementById('example');
  const editor = document.getElementById('raw_json');
  const count = document.getElementById('json-byte-count');
  const dataNode = document.getElementById('seeded-examples');
  const loadButton = document.getElementById('load-to-builder');
  const applyButton = document.getElementById('apply-builder');
  let examples = {};
  if (dataNode) {
    try { examples = JSON.parse(dataNode.textContent || '{}'); } catch (_error) { examples = {}; }
  }

  const byId = (id) => document.getElementById(id);
  const fields = {
    messageId: byId('b-message-id'), satelliteId: byId('b-satellite-id'),
    timestamp: byId('b-timestamp'), sequence: byId('b-sequence'),
    messageType: byId('b-message-type'), senderRole: byId('b-sender-role'),
    battery: byId('b-battery'), temperature: byId('b-temperature'), altitude: byId('b-altitude'),
    command: byId('b-command'), angle: byId('b-angle'), target: byId('b-target')
  };
  const telemetryFields = byId('b-telemetry-fields');
  const commandFields = byId('b-command-fields');
  const angleWrap = byId('b-angle-wrap');
  const targetWrap = byId('b-target-wrap');
  const builderStatus = byId('builder-status');

  function setStatus(message, isError = false) {
    if (!builderStatus) return;
    builderStatus.textContent = message;
    builderStatus.classList.toggle('status-error', isError);
  }

  function updateCount() {
    if (editor && count) {
      const bytes = new TextEncoder().encode(editor.value).length;
      count.textContent = `${bytes.toLocaleString()} bytes / 65,536 max`;
    }
  }

  function updatePayloadVisibility() {
    const isTelemetry = fields.messageType && fields.messageType.value === 'TELEMETRY';
    if (telemetryFields) telemetryFields.hidden = !isTelemetry;
    if (commandFields) commandFields.hidden = isTelemetry;
    const command = fields.command ? fields.command.value : '';
    if (angleWrap) angleWrap.hidden = command !== 'SET_ORIENTATION';
    if (targetWrap) targetWrap.hidden = command !== 'CAPTURE_IMAGE';
  }

  function parseIntoBuilder() {
    if (!editor) return;
    let obj;
    try {
      obj = JSON.parse(editor.value);
    } catch (error) {
      setStatus(`Could not load fields: JSON is invalid (${error.message}). Fix the JSON below first.`, true);
      return;
    }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      setStatus('The visual builder expects a JSON object. Use the raw editor for arrays or other custom inputs.', true);
      return;
    }
    const payload = obj.payload && typeof obj.payload === 'object' && !Array.isArray(obj.payload) ? obj.payload : {};
    fields.messageId.value = typeof obj.message_id === 'string' ? obj.message_id : '';
    fields.satelliteId.value = typeof obj.satellite_id === 'string' ? obj.satellite_id : '';
    fields.timestamp.value = typeof obj.timestamp === 'string' ? obj.timestamp : '';
    fields.sequence.value = obj.sequence_number ?? '';
    fields.messageType.value = obj.message_type === 'COMMAND' ? 'COMMAND' : 'TELEMETRY';
    const role = typeof obj.sender_role === 'string' ? obj.sender_role : 'satellite';
    fields.senderRole.value = ['satellite', 'ground_operator', 'mission_analyst', 'viewer'].includes(role) ? role : 'viewer';
    fields.battery.value = payload.battery_pct ?? '';
    fields.temperature.value = payload.temperature_c ?? '';
    fields.altitude.value = payload.altitude_km ?? '';
    const command = typeof payload.command === 'string' ? payload.command : 'REQUEST_STATUS';
    fields.command.value = ['REQUEST_STATUS', 'SET_ORIENTATION', 'CAPTURE_IMAGE', 'REBOOT_SENSOR'].includes(command) ? command : 'REQUEST_STATUS';
    fields.angle.value = payload.angle_deg ?? 45;
    fields.target.value = typeof payload.target === 'string' ? payload.target : 'cloud-pattern-07';
    updatePayloadVisibility();
    setStatus('Loaded the known fields from the current JSON. The raw editor preserves custom fields; applying the visual builder replaces the message with the fields shown here.');
  }

  function numberFromInput(input, label) {
    const raw = input.value.trim();
    if (!raw) throw new Error(`${label} is required in the visual builder. Use the raw JSON editor to test a missing field.`);
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) throw new Error(`${label} must be a finite number.`);
    return parsed;
  }

  function buildFromBuilder() {
    const messageType = fields.messageType.value;
    const message = {
      message_id: fields.messageId.value,
      satellite_id: fields.satelliteId.value,
      timestamp: fields.timestamp.value,
      sequence_number: numberFromInput(fields.sequence, 'Sequence number'),
      message_type: messageType,
      sender_role: fields.senderRole.value,
      payload: {}
    };
    if (messageType === 'TELEMETRY') {
      message.payload = {
        battery_pct: numberFromInput(fields.battery, 'Battery percentage'),
        temperature_c: numberFromInput(fields.temperature, 'Temperature'),
        altitude_km: numberFromInput(fields.altitude, 'Altitude')
      };
    } else {
      const command = fields.command.value;
      message.payload = { command };
      if (command === 'SET_ORIENTATION') message.payload.angle_deg = numberFromInput(fields.angle, 'Angle');
      if (command === 'CAPTURE_IMAGE') {
        if (!fields.target.value.trim()) throw new Error('Capture target is required. Use raw JSON to test a missing target.');
        message.payload.target = fields.target.value;
      }
    }
    editor.value = JSON.stringify(message, null, 2);
    editor.dispatchEvent(new Event('input', { bubbles: true }));
    setStatus('JSON updated (any old auth_tag was dropped). Review it, click “Sign with server key” if authentication is required, then “Validate message”.');
    editor.scrollIntoView({ behavior: 'smooth', block: 'center' });
    editor.focus({ preventScroll: true });
  }

  if (exampleSelect && editor) {
    exampleSelect.addEventListener('change', () => {
      const key = exampleSelect.value;
      if (Object.prototype.hasOwnProperty.call(examples, key)) {
        editor.value = JSON.stringify(examples[key], null, 2);
        updateCount();
        parseIntoBuilder();
      }
    });
    editor.addEventListener('input', () => {
      if (exampleSelect.value !== 'Custom JSON') exampleSelect.value = 'Custom JSON';
      updateCount();
      setStatus('Raw JSON changed. Validate it directly, or click “Load current JSON into fields” to edit the known fields visually.');
    });
  }

  if (fields.messageType) fields.messageType.addEventListener('change', () => {
    // Choose a role that makes the most common demo message valid by default.
    // Users can still select another role afterward to test authorization failures.
    if (fields.messageType.value === 'COMMAND' && fields.senderRole.value === 'satellite') {
      fields.senderRole.value = 'ground_operator';
    } else if (fields.messageType.value === 'TELEMETRY' && fields.senderRole.value !== 'satellite') {
      fields.senderRole.value = 'satellite';
    }
    updatePayloadVisibility();
    setStatus('Message type changed. Review the sender role and payload fields, then apply to JSON.');
  });
  if (fields.command) fields.command.addEventListener('change', updatePayloadVisibility);
  if (loadButton) loadButton.addEventListener('click', parseIntoBuilder);
  if (applyButton) applyButton.addEventListener('click', () => {
    try { buildFromBuilder(); }
    catch (error) { setStatus(error.message, true); }
  });

  Object.values(fields).forEach((field) => {
    if (!field) return;
    field.addEventListener('input', () => setStatus('You changed a field. Click “Apply fields to JSON” to transfer these edits to the raw JSON editor.'));
    field.addEventListener('change', updatePayloadVisibility);
  });

  // ---- HMAC authentication controls. The key stays on the server; JS only calls endpoints. ----
  const signButton = byId('sign-message');
  const tamperButton = byId('tamper-message');
  const modeButton = byId('toggle-auth-mode');
  const authStatus = byId('auth-status');
  const modeChip = byId('auth-mode-chip');

  function setAuthStatus(message, isError = false) {
    if (!authStatus) return;
    authStatus.textContent = message;
    authStatus.classList.toggle('status-error', isError);
  }

  async function postJson(url, body) {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    let data = {};
    try { data = await response.json(); } catch (_error) { /* non-JSON error body */ }
    if (!response.ok || data.ok === false) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  }

  if (signButton && editor) signButton.addEventListener('click', async () => {
    try {
      const data = await postJson(signButton.dataset.signUrl, { raw_json: editor.value });
      editor.value = data.signed_json;
      editor.dispatchEvent(new Event('input', { bubbles: true }));
      setAuthStatus('Signed on the server: auth_tag added. Changing any signed field now invalidates it. Click “Validate message”.');
    } catch (error) { setAuthStatus(error.message, true); }
  });

  if (tamperButton && editor) tamperButton.addEventListener('click', () => {
    let obj;
    try { obj = JSON.parse(editor.value); } catch (error) { setAuthStatus('JSON is invalid; fix it first.', true); return; }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj) || typeof obj.auth_tag !== 'string') {
      setAuthStatus('Sign the message first, then simulate tampering with its signed fields.', true);
      return;
    }
    const payload = obj.payload && typeof obj.payload === 'object' && !Array.isArray(obj.payload) ? obj.payload : null;
    const key = payload ? Object.keys(payload).find((k) => typeof payload[k] === 'number') : undefined;
    let what;
    if (key) {
      const before = payload[key];
      payload[key] = Math.round((before + 1) * 1000) / 1000;
      what = `payload.${key}: ${before} → ${payload[key]}`;
    } else {
      obj.message_id = `${obj.message_id || 'MSG'}-X`;
      what = 'message_id';
    }
    editor.value = JSON.stringify(obj, null, 2);
    editor.dispatchEvent(new Event('input', { bubbles: true }));
    setAuthStatus(`Tampered with ${what}. The old auth_tag was left unchanged, so verification should fail.`);
  });

  if (modeButton) modeButton.addEventListener('click', async () => {
    try {
      const data = await postJson(modeButton.dataset.modeUrl, { require: modeButton.dataset.required !== 'true' });
      modeButton.dataset.required = String(data.required);
      modeButton.textContent = data.required ? 'Make authentication optional' : 'Require authentication';
      if (modeChip) {
        modeChip.textContent = `AUTH ${data.required ? 'REQUIRED' : 'OPTIONAL'}`;
        modeChip.classList.toggle('auth-mode-on', data.required);
      }
      setAuthStatus(data.required ? 'Authentication is now required: unsigned messages will be rejected.' : 'Authentication is optional: unsigned messages skip the HMAC check, but a bad tag is still rejected.');
    } catch (error) { setAuthStatus(error.message, true); }
  });

  updateCount();
  updatePayloadVisibility();
  // Populate the visual builder with the initial sample so it is immediately editable.
  parseIntoBuilder();
})();
