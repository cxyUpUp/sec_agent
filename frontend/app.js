async function api(path, options = {}) {
  const authHeaders = {};
  if (authState.token) {
    authHeaders.Authorization = `Bearer ${authState.token}`;
  }
  const mergedHeaders = {
    "Content-Type": "application/json",
    ...authHeaders,
    ...(options.headers || {}),
  };
  const res = await fetch(path, {
    ...options,
    headers: mergedHeaders,
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  if (!res.ok) {
    throw new Error(typeof data === "string" ? data : JSON.stringify(data));
  }
  return data;
}

function byId(id) {
  return document.getElementById(id);
}

function pretty(value) {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function extractDisplayAnswer(rawAnswer) {
  if (typeof rawAnswer !== "string") return String(rawAnswer ?? "");
  const text = rawAnswer.trim();
  const fence = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  const normalized = fence ? fence[1].trim() : text;
  try {
    const parsed = JSON.parse(normalized);
    if (parsed && typeof parsed === "object") {
      if (parsed.params && typeof parsed.params.response === "string") {
        return parsed.params.response;
      }
      for (const key of ["response", "answer", "message", "content", "text"]) {
        if (typeof parsed[key] === "string") {
          return parsed[key];
        }
      }
      // Tool protocol JSON without readable response: hide protocol details from users.
      if (typeof parsed.action === "string" && parsed.params && typeof parsed.params === "object") {
        return "Tool executed. Result is available in trace panel.";
      }
    }
  } catch {
    // non-JSON answer, display directly
  }
  return normalized;
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const authState = {
  token: localStorage.getItem("sec_agent_token") || "",
  username: localStorage.getItem("sec_agent_username") || "",
};

const secureState = {
  userId: "",
  secureSessionId: "",
  sessionKey: null, // Uint8Array
  counter: 0,
};

function bytesToB64(bytes) {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(...arrs) {
  const size = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const a of arrs) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function randomHex(bytesLen = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(bytesLen));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function uint64be(num) {
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(0, Math.floor(num / 2 ** 32), false);
  view.setUint32(4, num >>> 0, false);
  return new Uint8Array(view.buffer);
}

async function sha256Bytes(...parts) {
  const merged = concatBytes(...parts);
  const digest = await crypto.subtle.digest("SHA-256", merged);
  return new Uint8Array(digest);
}

async function hmacHex(keyBytes, ...parts) {
  const k = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const msg = concatBytes(...parts);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
  return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function aesGcmEncrypt(keyBytes, plaintextBytes, aadBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aadBytes }, key, plaintextBytes)
  );
  return { nonce, cipher };
}

async function aesGcmDecrypt(keyBytes, nonceBytes, ciphertextBytes, aadBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonceBytes, additionalData: aadBytes },
      key,
      ciphertextBytes
    )
  );
  return plain;
}

function secureAadForChat(secureSessionId, counter) {
  return concatBytes(enc.encode(secureSessionId), enc.encode("|"), uint64be(counter));
}

async function ratchetKey(keyBytes, counter) {
  return sha256Bytes(keyBytes, enc.encode("|ratchet|"), uint64be(counter));
}

function updateSecureStatus(text) {
  byId("secureStatus").textContent = text;
}

function updateAuthUI() {
  const loggedIn = Boolean(authState.token && authState.username);
  byId("authStatus").textContent = loggedIn ? `Signed in as ${authState.username}` : "Not signed in";
  byId("authHint").textContent = loggedIn ? "Authenticated. You can now use agent chat." : "Please register/login first.";
  byId("sendBtn").disabled = !loggedIn;
  byId("secureMode").disabled = !loggedIn;
  byId("sessionBtn").disabled = !loggedIn;
  byId("evalBtn").disabled = !loggedIn;
  byId("resetSecureBtn").disabled = !loggedIn;
  byId("message").disabled = !loggedIn;
  byId("userId").value = authState.username || "demo_user";
}

function setAuth(token, username) {
  authState.token = token;
  authState.username = username;
  if (token) {
    localStorage.setItem("sec_agent_token", token);
    localStorage.setItem("sec_agent_username", username);
  } else {
    localStorage.removeItem("sec_agent_token");
    localStorage.removeItem("sec_agent_username");
  }
  updateAuthUI();
}

function appendBubble(role, text) {
  const chatLog = byId("chatLog");
  if (!chatLog) return;
  const div = document.createElement("div");
  div.className = `bubble ${role === "user" ? "bubble-user" : "bubble-agent"}`;
  div.textContent = text;
  chatLog.appendChild(div);
  chatLog.scrollTop = chatLog.scrollHeight;
}

function resetSecureSession() {
  secureState.userId = "";
  secureState.secureSessionId = "";
  secureState.sessionKey = null;
  secureState.counter = 0;
  updateSecureStatus("Secure mode: session reset");
}

async function ensureSecureSession(userId, passphrase) {
  if (secureState.userId === userId && secureState.secureSessionId && secureState.sessionKey) {
    return;
  }
  const clientNonce = randomHex(16);
  const alphaBytes = await sha256Bytes(enc.encode(`${passphrase}|${clientNonce}`));
  const alpha = Array.from(alphaBytes, (b) => b.toString(16).padStart(2, "0")).join("");

  const ecdhKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const clientPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ecdhKeyPair.publicKey));

  const start = await api("/pcka/handshake/start", {
    method: "POST",
    body: JSON.stringify({
      alpha,
      client_nonce: clientNonce,
      client_pubkey_b64: bytesToB64(clientPubRaw),
    }),
  });

  const serverPubRaw = b64ToBytes(start.server_pubkey_b64);
  const sid = b64ToBytes(start.sid);
  const serverPubKey = await crypto.subtle.importKey(
    "raw",
    serverPubRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: serverPubKey }, ecdhKeyPair.privateKey, 256)
  );
  const hkdfBase = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveBits"]);
  const dhKey = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: sid,
        info: enc.encode(`sec-agent-ecdh|${clientNonce}|${start.server_nonce}`),
      },
      hkdfBase,
      256
    )
  );

  const sessionKey = await sha256Bytes(
    enc.encode(alpha),
    enc.encode(start.beta),
    sid,
    enc.encode(clientNonce),
    enc.encode(start.server_nonce)
  );
  const clientProof = await hmacHex(
    sessionKey,
    enc.encode("client_finish"),
    enc.encode(alpha),
    enc.encode(start.beta)
  );
  const payload = enc.encode(
    JSON.stringify({
      session_key_b64: bytesToB64(sessionKey),
      client_proof: clientProof,
    })
  );
  const aad = enc.encode(`${start.handshake_id}|${alpha}|${start.beta}`);
  const sealed = await aesGcmEncrypt(dhKey, payload, aad);

  const finish = await api("/pcka/handshake/finish", {
    method: "POST",
    body: JSON.stringify({
      handshake_id: start.handshake_id,
      encrypted_session_key_b64: bytesToB64(sealed.cipher),
      nonce_b64: bytesToB64(sealed.nonce),
    }),
  });

  const expectedServerProof = await hmacHex(sessionKey, enc.encode("server_finish"));
  if (finish.server_proof !== expectedServerProof) {
    throw new Error("Server proof verification failed");
  }

  secureState.userId = userId;
  secureState.secureSessionId = finish.secure_session_id;
  secureState.sessionKey = sessionKey;
  secureState.counter = 0;
  updateSecureStatus(`Secure mode: established (${finish.secure_session_id.slice(0, 8)}...)`);
}

async function sendSecureMessage(userId, message) {
  const passphrase = byId("passphrase").value || "demo-pass-123";
  await ensureSecureSession(userId, passphrase);

  const aad = secureAadForChat(secureState.secureSessionId, secureState.counter);
  const sealedReq = await aesGcmEncrypt(secureState.sessionKey, enc.encode(message), aad);
  const resp = await api("/chat/secure", {
    method: "POST",
    body: JSON.stringify({
      secure_session_id: secureState.secureSessionId,
      nonce_b64: bytesToB64(sealedReq.nonce),
      ciphertext_b64: bytesToB64(sealedReq.cipher),
    }),
  });

  const plain = await aesGcmDecrypt(
    secureState.sessionKey,
    b64ToBytes(resp.nonce_b64),
    b64ToBytes(resp.ciphertext_b64),
    aad
  );
  const data = JSON.parse(dec.decode(plain));

  const currentCounter = secureState.counter;
  secureState.sessionKey = await ratchetKey(secureState.sessionKey, currentCounter);
  secureState.counter = currentCounter + 1;
  updateSecureStatus(
    `Secure mode: active (${secureState.secureSessionId.slice(0, 8)}..., counter=${secureState.counter})`
  );

  return data;
}

async function sendMessage() {
  if (!authState.token) {
    appendBubble("agent", "Please login first.");
    return;
  }
  const userId = byId("userId").value.trim() || "demo_user";
  const message = byId("message").value.trim();
  if (!message) return;
  const secureMode = byId("secureMode").checked;
  appendBubble("user", message);
  byId("answer").textContent = "Sending...";
  byId("trace").textContent = "";
  byId("message").value = "";
  try {
    const data = secureMode
      ? await sendSecureMessage(userId, message)
      : await api("/chat", {
          method: "POST",
          body: JSON.stringify({ message }),
        });
    const displayAnswer = extractDisplayAnswer(data.answer);
    byId("answer").textContent = displayAnswer;
    byId("trace").textContent = pretty(data.security_trace);
    appendBubble("agent", displayAnswer);
  } catch (err) {
    byId("answer").textContent = "Request failed";
    byId("trace").textContent = String(err);
    appendBubble("agent", `Request failed: ${String(err)}`);
  }
}

async function getSession() {
  if (!authState.token) return;
  const userId = byId("userId").value.trim() || "demo_user";
  byId("meta").textContent = "Loading session...";
  try {
    const data = await api(`/session/${encodeURIComponent(userId)}`);
    byId("meta").textContent = pretty(data);
  } catch (err) {
    byId("meta").textContent = String(err);
  }
}

async function runEval() {
  if (!authState.token) return;
  byId("meta").textContent = "Running eval...";
  try {
    const data = await api("/eval");
    byId("meta").textContent = pretty(data);
  } catch (err) {
    byId("meta").textContent = String(err);
  }
}

async function registerUser() {
  const username = byId("authUser").value.trim();
  const password = byId("authPass").value;
  if (!username || !password) {
    byId("authHint").textContent = "Username and password are required.";
    return;
  }
  try {
    await api("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password }),
      headers: { Authorization: "" },
    });
    byId("authHint").textContent = "Register success. Please login.";
  } catch (err) {
    byId("authHint").textContent = `Register failed: ${String(err)}`;
  }
}

async function loginUser() {
  const username = byId("authUser").value.trim();
  const password = byId("authPass").value;
  if (!username || !password) {
    byId("authHint").textContent = "Username and password are required.";
    return;
  }
  try {
    const data = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
      headers: { Authorization: "" },
    });
    setAuth(data.token, data.username);
    resetSecureSession();
    byId("authHint").textContent = "Login success.";
    appendBubble("agent", `Welcome ${data.username}, you are now authenticated.`);
  } catch (err) {
    byId("authHint").textContent = `Login failed: ${String(err)}`;
  }
}

function logoutUser() {
  setAuth("", "");
  resetSecureSession();
  byId("authHint").textContent = "Logged out.";
}

async function bootstrapAuth() {
  updateAuthUI();
  if (!authState.token) return;
  try {
    const me = await api("/auth/me");
    setAuth(authState.token, me.username);
  } catch {
    setAuth("", "");
  }
}

byId("sendBtn").addEventListener("click", sendMessage);
byId("resetSecureBtn").addEventListener("click", resetSecureSession);
byId("sessionBtn").addEventListener("click", getSession);
byId("evalBtn").addEventListener("click", runEval);
byId("registerBtn").addEventListener("click", registerUser);
byId("loginBtn").addEventListener("click", loginUser);
byId("logoutBtn").addEventListener("click", logoutUser);
byId("secureMode").addEventListener("change", (e) => {
  if (!e.target.checked) {
    updateSecureStatus("Secure mode: off");
    return;
  }
  updateSecureStatus("Secure mode: on (handshake on first send)");
});

byId("message").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

bootstrapAuth();
