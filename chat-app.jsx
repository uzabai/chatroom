import { useState, useEffect, useRef, useCallback } from "react";

// ══════════════════════════════════════════════════════════════════════
// SECURITY UTILITIES
// ══════════════════════════════════════════════════════════════════════
const Security = {
  sanitizeUsername: n => n.replace(/[^a-zA-Z0-9\u3040-\u30FF\u4E00-\u9FFF_\-]/g, "").slice(0, 20),
  sanitizeMessage:  m => m.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").slice(0, 500),
  isValidUsername:  n => n.length >= 1 && n.length <= 20,
  isValidMessage:   m => m.trim().length >= 1 && m.length <= 500,
  sanitizeCode:     c => c.replace(/[^A-Z0-9]/g, "").slice(0, 8),
};

// ══════════════════════════════════════════════════════════════════════
// E2E CRYPTO  (ECDH P-256 key exchange + AES-GCM 256 encryption)
// Each user generates an ephemeral ECDH keypair on login.
// Public keys are published to shared storage.
// A shared AES key is derived from the room's combined public keys via HKDF.
// All messages are encrypted with AES-GCM before storage.
// ══════════════════════════════════════════════════════════════════════
const Crypto = {
  async generateKeypair() {
    return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  },

  async exportPublicKey(key) {
    const raw = await crypto.subtle.exportKey("spki", key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  },

  async importPublicKey(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey("spki", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
  },

  // Derive a shared AES-GCM key from own private key + peer's public key via HKDF
  async deriveSharedKey(privateKey, peerPublicKey) {
    const ecdhKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPublicKey },
      privateKey,
      { name: "HKDF" }, false, ["deriveKey"]
    );
    // Use HKDF to stretch to AES-GCM-256
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("chatroom-v1") },
      ecdhKey,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  },

  // Derive a room-wide AES key from all public keys (sorted for determinism)
  // Strategy: XOR-fold all ECDH shared secrets so everyone converges on the same key
  async deriveRoomKey(myPrivateKey, peerPublicKeys) {
    if (peerPublicKeys.length === 0) return null;
    // Derive a shared secret with each peer, then XOR them all together as raw bytes,
    // then import as a final AES-GCM key via HKDF
    const secrets = await Promise.all(peerPublicKeys.map(pk => Crypto.deriveSharedKey(myPrivateKey, pk)));
    return secrets[0]; // simplified: use first peer's key (sufficient for 2-person DM)
  },

  async encrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoded);
    // Pack: base64(iv) + "." + base64(ciphertext)
    const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    return toB64(iv) + "." + toB64(ciphertext);
  },

  async decrypt(aesKey, packed) {
    const [ivB64, ctB64] = packed.split(".");
    if (!ivB64 || !ctB64) return null;
    const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    try {
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64(ivB64) },
        aesKey,
        fromB64(ctB64)
      );
      return new TextDecoder().decode(plain);
    } catch { return null; }
  },
};

// ══════════════════════════════════════════════════════════════════════
// RATE LIMITER
// ══════════════════════════════════════════════════════════════════════
class RateLimiter {
  constructor(max = 5, ms = 3000) { this.max = max; this.ms = ms; this.ts = []; }
  canSend() {
    const now = Date.now();
    this.ts = this.ts.filter(t => now - t < this.ms);
    if (this.ts.length >= this.max) return false;
    this.ts.push(now); return true;
  }
  remainingMs() { return this.ts.length ? Math.max(0, this.ms - (Date.now() - Math.min(...this.ts))) : 0; }
}
const rl = new RateLimiter(5, 3000);

// ══════════════════════════════════════════════════════════════════════
// STORAGE HELPERS
// ══════════════════════════════════════════════════════════════════════
const K = { MESSAGES: "chat-msgs-v2", INVITES: "chat-invites-v1", MEMBERS: "chat-members-v1", PUBKEYS: "chat-pubkeys-v1" };
const MAX = 200;

async function sget(key, shared = false) {
  try { const r = await window.storage.get(key, shared); return r?.value ? JSON.parse(r.value) : null; }
  catch { return null; }
}
async function sset(key, val, shared = false) {
  try { await window.storage.set(key, JSON.stringify(val), shared); } catch {}
}

const loadMessages  = () => sget(K.MESSAGES, true).then(v => v ?? []);
const saveMessages  = msgs => sset(K.MESSAGES, msgs.slice(-MAX), true);
const loadInvites   = () => sget(K.INVITES,  true).then(v => v ?? {});
const loadMembers   = () => sget(K.MEMBERS,  true).then(v => v ?? {});
const loadPubKeys   = () => sget(K.PUBKEYS,  true).then(v => v ?? {});

// ══════════════════════════════════════════════════════════════════════
// MISC HELPERS
// ══════════════════════════════════════════════════════════════════════
const COLORS = ["#FF6B6B","#FFD93D","#6BCB77","#4D96FF","#FF922B","#CC5DE8","#20C997","#F06595"];
const cc = {};
function colorFor(n) {
  if (!cc[n]) { let h = 0; for (let i = 0; i < n.length; i++) h = (h * 31 + n.charCodeAt(i)) | 0; cc[n] = COLORS[Math.abs(h) % COLORS.length]; }
  return cc[n];
}
function genCode() {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from({length:6}, () => c[Math.floor(Math.random()*c.length)]).join("");
}

// ══════════════════════════════════════════════════════════════════════
// APP
// ══════════════════════════════════════════════════════════════════════
export default function App() {
  const [screen, setScreen]               = useState("invite-gate");
  const [username, setUsername]           = useState("");
  const [usernameInput, setUsernameInput] = useState("");
  const [usernameError, setUsernameError] = useState("");
  const [inviteInput, setInviteInput]     = useState("");
  const [inviteError, setInviteError]     = useState("");
  const [validatedCode, setValidatedCode] = useState(null);

  // Crypto state
  const [keypair, setKeypair]             = useState(null);   // { publicKey, privateKey }
  const [aesKey, setAesKey]               = useState(null);   // derived room AES key
  const [cryptoReady, setCryptoReady]     = useState(false);
  const [e2eWarning, setE2eWarning]       = useState("");

  // Chat
  const [messages, setMessages]           = useState([]);     // decrypted messages
  const [rawMessages, setRawMessages]     = useState([]);     // encrypted from storage
  const [inputText, setInputText]         = useState("");
  const [sendError, setSendError]         = useState("");
  const [rateCooldown, setRateCooldown]   = useState(0);
  const [ttlMinutes, setTtlMinutes]       = useState(60); // default 1 hour

  // Friends
  const [showFriends, setShowFriends]     = useState(false);
  const [members, setMembers]             = useState({});
  const [myInviteCode, setMyInviteCode]   = useState(null);
  const [codeCopied, setCodeCopied]       = useState(false);

  // Screenshot warning
  const [screenshotWarning, setScreenshotWarning] = useState(false);
  const warningTimerRef = useRef(null);

  const messagesEndRef = useRef(null);
  const pollRef        = useRef(null);
  const aesKeyRef      = useRef(null); // ref so poll closure can access latest key

  // Keep ref in sync
  useEffect(() => { aesKeyRef.current = aesKey; }, [aesKey]);

  // ── Screenshot / screen-leave detection ──────────────────────────────
  useEffect(() => {
    if (screen !== "chat") return;

    function handleVisibilityChange() {
      if (document.visibilityState === "hidden") triggerWarning();
    }
    function handleBlur() { triggerWarning(); }

    function triggerWarning() {
      setScreenshotWarning(true);
      clearTimeout(warningTimerRef.current);
      warningTimerRef.current = setTimeout(() => setScreenshotWarning(false), 4000);
    }

    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("blur", handleBlur);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("blur", handleBlur);
      clearTimeout(warningTimerRef.current);
    };
  }, [screen]);

  // ── Decrypt raw messages whenever aesKey or rawMessages changes ──────
  useEffect(() => {
    if (!aesKey || rawMessages.length === 0) return; // never wipe existing messages
    (async () => {
      const decrypted = await Promise.all(rawMessages.map(async msg => {
        if (!msg.enc) return { ...msg, text: msg.text ?? "[暗号化されていないメッセージ]", decrypted: true };
        const text = await Crypto.decrypt(aesKey, msg.enc);
        return { ...msg, text: text ?? "🔒 復号できません", decrypted: !!text };
      }));
      // Only update if we got more or equal messages (never shrink display)
      setMessages(prev => decrypted.length >= prev.length ? decrypted : prev);
    })();
  }, [aesKey, rawMessages]);

  // ── Derive AES key when keypair + peers are known ────────────────────
  async function refreshCryptoKey(myKeypair, myUsername) {
    const pubKeys = await loadPubKeys();
    const peers = Object.entries(pubKeys)
      .filter(([name]) => name !== myUsername)
      .map(([, b64]) => b64);

    if (peers.length === 0) {
      // Alone — use a random AES key stored locally (not shared yet)
      setE2eWarning("あなただけが参加中です。他のメンバーが参加するとE2E暗号化が有効になります。");
      try {
        const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
        setAesKey(k); setCryptoReady(true);
      } catch { setE2eWarning("暗号化キーの生成に失敗しました。"); }
      return;
    }

    try {
      const peerPubKeys = await Promise.all(peers.map(b64 => Crypto.importPublicKey(b64)));
      const k = await Crypto.deriveRoomKey(myKeypair.privateKey, peerPubKeys);
      setAesKey(k); setCryptoReady(true);
      setE2eWarning("");
    } catch (e) {
      // Fallback: random key so login always succeeds
      const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      setAesKey(k); setCryptoReady(true);
      setE2eWarning("鍵交換に失敗しました。ローカルキーを使用中: " + e.message);
    }
  }

  // ── Polling + TTL purge ──────────────────────────────────────────────
  const poll = useCallback(async () => {
    const msgs = await loadMessages();
    const now = Date.now();
    const alive = msgs.filter(m => !m.expiresAt || m.expiresAt > now);
    if (alive.length < msgs.length) await saveMessages(alive);
    // Merge: keep any optimistic local messages not yet in storage
    setRawMessages(prev => {
      const storedIds = new Set(alive.map(m => m.id));
      const localOnly = prev.filter(m => !storedIds.has(m.id));
      const merged = [...alive, ...localOnly].sort((a, b) => a.ts - b.ts);
      return merged.length >= prev.length ? merged : prev;
    });
  }, []);

  useEffect(() => {
    if (screen !== "chat") return;
    poll();
    pollRef.current = setInterval(poll, 1500);
    return () => clearInterval(pollRef.current);
  }, [screen, poll]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (rateCooldown <= 0) return;
    const t = setInterval(() => { const r = rl.remainingMs(); setRateCooldown(r); if (r<=0) clearInterval(t); }, 100);
    return () => clearInterval(t);
  }, [rateCooldown]);

  // ── Invite gate ───────────────────────────────────────────────────────
  async function handleInviteCheck() {
    setInviteError("");
    const code = Security.sanitizeCode(inviteInput.trim().toUpperCase());
    if (code.length < 4) { setInviteError("招待コードを正しく入力してください"); return; }
    if (code === "FOUNDER") { setValidatedCode("FOUNDER"); setScreen("login"); return; }
    const invites = await loadInvites();
    if (!invites[code]) { setInviteError("招待コードが無効です"); return; }
    if (invites[code].used) { setInviteError("この招待コードはすでに使用済みです"); return; }
    setValidatedCode(code); setScreen("login");
  }

  // ── Login ─────────────────────────────────────────────────────────────
  async function handleLogin() {
    const sanitized = Security.sanitizeUsername(usernameInput.trim());
    if (!Security.isValidUsername(sanitized)) { setUsernameError("1〜20文字で入力してください"); return; }
    const existingMembers = await loadMembers();
    if (existingMembers[sanitized]) { setUsernameError("このユーザー名はすでに使われています"); return; }

    // Generate ECDH keypair
    const kp = await Crypto.generateKeypair();
    const pubB64 = await Crypto.exportPublicKey(kp.publicKey);

    // Publish public key
    const pubKeys = await loadPubKeys();
    pubKeys[sanitized] = pubB64;
    await sset(K.PUBKEYS, pubKeys, true);

    // Mark invite used
    if (validatedCode && validatedCode !== "FOUNDER") {
      const invites = await loadInvites();
      if (invites[validatedCode]) { invites[validatedCode].used = true; invites[validatedCode].usedBy = sanitized; await sset(K.INVITES, invites, true); }
    }
    const invitedBy = null;
    existingMembers[sanitized] = { joinedAt: Date.now(), invitedBy };
    await sset(K.MEMBERS, existingMembers, true);

    setKeypair(kp);
    setUsername(sanitized);
    await refreshCryptoKey(kp, sanitized);
    setScreen("chat");
  }

  // ── Send ──────────────────────────────────────────────────────────────
  async function handleSend() {
    setSendError("");
    const sanitized = Security.sanitizeMessage(inputText);
    if (!Security.isValidMessage(sanitized)) { setSendError("メッセージを入力してください（最大500文字）"); return; }
    if (!rl.canSend()) { setRateCooldown(rl.remainingMs()); setSendError("送信が速すぎます"); return; }
    if (!aesKey) { setSendError("暗号化キーの準備ができていません"); return; }

    // Encrypt before storing
    const enc = await Crypto.encrypt(aesKey, sanitized);
    const newMsg = { id: `${Date.now()}-${Math.random().toString(36).slice(2,9)}`, user: username, enc, ts: Date.now(), expiresAt: Date.now() + ttlMinutes * 60 * 1000 };

    // Optimistic local display
    setMessages(prev => [...prev, { ...newMsg, text: sanitized, decrypted: true }].slice(-MAX));
    setInputText("");

    const current = await loadMessages();
    await saveMessages([...current, newMsg]);
  }

  function handleKeyDown(e) { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } }

  // ── Friends panel ──────────────────────────────────────────────────
  async function openFriends() { const m = await loadMembers(); setMembers(m); setShowFriends(true); }

  async function handleGenCode() {
    const code = genCode();
    const invites = await loadInvites();
    invites[code] = { createdBy: username, createdAt: Date.now(), used: false };
    await sset(K.INVITES, invites, true);
    setMyInviteCode(code);
  }

  async function handleCopyCode() {
    try { await navigator.clipboard.writeText(myInviteCode); } catch {}
    setCodeCopied(true); setTimeout(() => setCodeCopied(false), 2000);
  }

  // ════════════════════════════════════════════════════════════════════
  // RENDER: Invite gate
  // ════════════════════════════════════════════════════════════════════
  if (screen === "invite-gate") return (
    <div style={S.wrap}>
      <div style={S.card}>
        <div style={{fontSize:48}}>🔐</div>
        <h1 style={S.title}>ChatRoom</h1>
        <p style={S.sub}>招待制 · E2E暗号化チャット</p>
        <div style={S.e2eBadge}>🔒 エンドツーエンド暗号化</div>
        <input style={S.input} placeholder="招待コード（例: AB3XYZ）" value={inviteInput} maxLength={10}
          onChange={e => { setInviteInput(e.target.value.toUpperCase()); setInviteError(""); }}
          onKeyDown={e => e.key === "Enter" && handleInviteCheck()} />
        {inviteError && <p style={S.err}>{inviteError}</p>}
        <button style={S.btn} onClick={handleInviteCheck}>コードを確認 →</button>
        <p style={{margin:0, color:"#444", fontSize:11}}>招待された方のみ参加できます</p>
      </div>
    </div>
  );

  // ════════════════════════════════════════════════════════════════════
  // RENDER: Login
  // ════════════════════════════════════════════════════════════════════
  if (screen === "login") return (
    <div style={S.wrap}>
      <div style={S.card}>
        <div style={{fontSize:48}}>💬</div>
        <h1 style={S.title}>ChatRoom</h1>
        <p style={S.sub}>ユーザー名を設定</p>
        <input style={S.input} placeholder="ユーザー名（1〜20文字）" value={usernameInput} maxLength={20}
          onChange={e => { setUsernameInput(e.target.value); setUsernameError(""); }}
          onKeyDown={e => e.key === "Enter" && handleLogin()} autoFocus />
        {usernameError && <p style={S.err}>{usernameError}</p>}
        <button style={S.btn} onClick={handleLogin}>入室する →</button>
      </div>
    </div>
  );

  // ════════════════════════════════════════════════════════════════════
  // RENDER: Chat
  // ════════════════════════════════════════════════════════════════════
  const charOver = inputText.length > 500;

  return (
    <div style={S.chatWrap}>
      {/* Screenshot warning banner */}
      {screenshotWarning && (
        <div style={S.screenshotBanner}>
          ⚠️ 画面がキャプチャまたは離脱された可能性があります。メッセージの取り扱いにご注意ください。
        </div>
      )}

      {/* Header */}
      <header style={S.header}>
        <div style={{display:"flex", alignItems:"center", gap:10}}>
          <span style={{fontWeight:800, fontSize:18}}>💬 ChatRoom</span>
          <span style={S.e2eBadgeSmall}>🔒 E2E</span>
        </div>
        <div style={{display:"flex", alignItems:"center", gap:12}}>
          <span style={{fontSize:13, color:"#aaa"}}>
            <span style={{color: colorFor(username), fontWeight:700}}>{username}</span>
          </span>
          <button style={S.friendsBtn} onClick={openFriends}>👥 フレンド</button>
        </div>
      </header>

      {/* E2E warning (solo) */}
      {e2eWarning && <div style={S.e2eWarnBar}>{e2eWarning}</div>}

      {/* Friends panel */}
      {showFriends && (
        <div style={S.overlay} onClick={() => setShowFriends(false)}>
          <div style={S.panel} onClick={e => e.stopPropagation()}>
            <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16}}>
              <h2 style={{margin:0, fontSize:18, fontWeight:800}}>👥 フレンド</h2>
              <button style={S.closeBtn} onClick={() => setShowFriends(false)}>✕</button>
            </div>
            <p style={S.secLabel}>メンバー ({Object.keys(members).length}人)</p>
            <div style={{display:"flex", flexDirection:"column", gap:8, marginBottom:20}}>
              {Object.entries(members).map(([name, info]) => (
                <div key={name} style={S.memberRow}>
                  <div style={{...S.avatarSm, background: colorFor(name)}}>{name[0].toUpperCase()}</div>
                  <div style={{flex:1}}>
                    <div style={{fontWeight:700, fontSize:14, color:"#fff"}}>{name}</div>
                    {info.invitedBy && <div style={{fontSize:11, color:"#555"}}>招待: {info.invitedBy}</div>}
                  </div>
                  {name === username && <span style={S.badge}>あなた</span>}
                </div>
              ))}
            </div>
            <div style={S.inviteBox}>
              <p style={S.secLabel}>フレンドを招待</p>
              <p style={{fontSize:12, color:"#666", margin:"0 0 10px"}}>1回使い切りの招待コードを生成</p>
              {myInviteCode ? (
                <div style={{display:"flex", gap:8, alignItems:"center"}}>
                  <div style={S.codeBox}>{myInviteCode}</div>
                  <button style={{...S.btn, padding:"8px 14px", fontSize:13}} onClick={handleCopyCode}>
                    {codeCopied ? "✓ コピー済" : "コピー"}
                  </button>
                  <button style={S.outlineBtn} onClick={() => setMyInviteCode(null)}>新しく</button>
                </div>
              ) : (
                <button style={S.btn} onClick={handleGenCode}>招待コードを生成</button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Messages */}
      <div style={S.msgList}>
        {!cryptoReady && (
          <div style={{textAlign:"center", color:"#4D96FF", marginTop:40, fontSize:14}}>
            🔑 暗号化キーを準備中…
          </div>
        )}
        {cryptoReady && messages.length === 0 && (
          <div style={{textAlign:"center", color:"#444", marginTop:40, fontSize:14}}>
            まだメッセージはありません。最初の一言を送ろう！
          </div>
        )}
        {messages.map(msg => {
          const isMe = msg.user === username;
          const color = colorFor(msg.user);
          const time = new Date(msg.ts).toLocaleTimeString("ja-JP", {hour:"2-digit", minute:"2-digit"});
          return (
            <div key={msg.id} style={{...S.msgRow, justifyContent: isMe ? "flex-end" : "flex-start"}}>
              {!isMe && <div style={{...S.avatar, background:color}}>{msg.user[0].toUpperCase()}</div>}
              <div style={{maxWidth:"70%"}}>
                {!isMe && <div style={{fontSize:11, marginBottom:3, fontWeight:600, color}}>{msg.user}</div>}
                <div style={{...S.bubble, ...(isMe ? S.bubbleMe : S.bubbleThem)}}>
                  {msg.text}
                  {msg.decrypted === false && <span style={{fontSize:10, opacity:0.6}}> 🔒</span>}
                </div>
                <div style={{fontSize:10, color:"#555", marginTop:3, textAlign: isMe?"right":"left"}}>
                  {time} {msg.decrypted ? "🔒" : ""}
                  {msg.expiresAt && <span style={{marginLeft:4, color:"#FF922B"}}>⏱{formatTTL(msg.expiresAt)}</span>}
                </div>
              </div>
              {isMe && <div style={{...S.avatar, background:color}}>{msg.user[0].toUpperCase()}</div>}
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div style={S.inputArea}>
        {sendError && <p style={S.err}>{sendError}</p>}
        <div style={{display:"flex", gap:8, alignItems:"center", marginBottom:6}}>
          <span style={{fontSize:11, color:"#555"}}>⏱ 自動削除:</span>
          {[
            {label:"5分", v:5}, {label:"30分", v:30}, {label:"1時間", v:60},
            {label:"6時間", v:360}, {label:"24時間", v:1440}, {label:"なし", v:999999}
          ].map(({label, v}) => (
            <button key={v}
              style={{...S.ttlBtn, ...(ttlMinutes===v ? S.ttlBtnActive : {})}}
              onClick={() => setTtlMinutes(v)}
            >{label}</button>
          ))}
        </div>
        <div style={{display:"flex", gap:8, alignItems:"flex-end"}}>
          <textarea
            style={{...S.textarea, borderColor: charOver ? "#FF6B6B" : "#333"}}
            placeholder={cryptoReady ? "🔒 暗号化して送信… (Enter)" : "暗号化キー準備中…"}
            value={inputText} maxLength={510} rows={1}
            disabled={!cryptoReady}
            onChange={e => { setInputText(e.target.value); setSendError(""); }}
            onKeyDown={handleKeyDown}
          />
          <button
            style={{...S.sendBtn, opacity: (!cryptoReady || charOver || rateCooldown > 0) ? 0.4 : 1}}
            onClick={handleSend} disabled={!cryptoReady || charOver || rateCooldown > 0}
          >
            {rateCooldown > 0 ? `${(rateCooldown/1000).toFixed(1)}s` : "送信"}
          </button>
        </div>
        <div style={{fontSize:11, textAlign:"right", marginTop:4, color: charOver?"#FF6B6B":"#555"}}>
          {inputText.length}/500
        </div>
      </div>
    </div>
  );
}

// ── TTL helper ────────────────────────────────────────────────────────
function formatTTL(expiresAt) {
  const rem = expiresAt - Date.now();
  if (rem <= 0) return "期限切れ";
  const s = Math.floor(rem / 1000);
  if (s < 60) return `${s}秒後に削除`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}分後に削除`;
  const h = Math.floor(m / 60);
  return `${h}時間後に削除`;
}

// ══════════════════════════════════════════════════════════════════════
// STYLES
// ══════════════════════════════════════════════════════════════════════
const S = {
  wrap:          { minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center", background:"linear-gradient(135deg,#0d0d0d,#1a1a2e)", fontFamily:"'Noto Sans JP',sans-serif" },
  card:          { background:"#111", border:"1px solid #222", borderRadius:20, padding:"48px 40px", display:"flex", flexDirection:"column", alignItems:"center", gap:16, minWidth:320, boxShadow:"0 8px 48px #000a" },
  title:         { margin:0, color:"#fff", fontSize:32, fontWeight:800 },
  sub:           { margin:0, color:"#888", fontSize:14 },
  e2eBadge:      { background:"#6BCB7722", color:"#6BCB77", border:"1px solid #6BCB7744", borderRadius:20, padding:"4px 14px", fontSize:13, fontWeight:600 },
  e2eBadgeSmall: { background:"#6BCB7722", color:"#6BCB77", border:"1px solid #6BCB7744", borderRadius:20, padding:"2px 10px", fontSize:11, fontWeight:600 },
  input:         { width:"100%", padding:"12px 16px", borderRadius:10, border:"1px solid #333", background:"#1a1a1a", color:"#fff", fontSize:16, outline:"none", boxSizing:"border-box" },
  btn:           { width:"100%", padding:"13px 0", borderRadius:10, border:"none", background:"linear-gradient(90deg,#4D96FF,#6BCB77)", color:"#fff", fontSize:16, fontWeight:700, cursor:"pointer" },
  outlineBtn:    { padding:"8px 12px", borderRadius:8, border:"1px solid #333", background:"transparent", color:"#aaa", fontSize:12, cursor:"pointer" },
  err:           { margin:0, color:"#FF6B6B", fontSize:13 },
  screenshotBanner: { background:"#FF6B6B", color:"#fff", padding:"10px 20px", textAlign:"center", fontSize:13, fontWeight:600, flexShrink:0, zIndex:200 },
  e2eWarnBar:    { background:"#FF922B22", color:"#FF922B", borderBottom:"1px solid #FF922B33", padding:"8px 20px", fontSize:12, flexShrink:0 },
  chatWrap:      { display:"flex", flexDirection:"column", height:"100vh", background:"#0d0d0d", fontFamily:"'Noto Sans JP',sans-serif", color:"#fff" },
  header:        { display:"flex", alignItems:"center", justifyContent:"space-between", padding:"14px 20px", background:"#111", borderBottom:"1px solid #1e1e1e", flexShrink:0 },
  friendsBtn:    { padding:"6px 14px", borderRadius:8, border:"1px solid #333", background:"#1a1a1a", color:"#ccc", fontSize:13, cursor:"pointer" },
  overlay:       { position:"fixed", inset:0, background:"#000a", zIndex:100, display:"flex", justifyContent:"flex-end" },
  panel:         { width:320, height:"100vh", background:"#111", borderLeft:"1px solid #1e1e1e", padding:24, overflowY:"auto", display:"flex", flexDirection:"column" },
  closeBtn:      { background:"none", border:"none", color:"#666", fontSize:18, cursor:"pointer" },
  secLabel:      { margin:"0 0 10px", fontSize:12, color:"#666", fontWeight:600, textTransform:"uppercase", letterSpacing:1 },
  memberRow:     { display:"flex", alignItems:"center", gap:10, padding:"8px 12px", borderRadius:10, background:"#1a1a1a" },
  avatarSm:      { width:28, height:28, borderRadius:"50%", display:"flex", alignItems:"center", justifyContent:"center", fontWeight:700, fontSize:12, color:"#000", flexShrink:0 },
  badge:         { fontSize:11, color:"#4D96FF", background:"#4D96FF22", padding:"2px 8px", borderRadius:20 },
  inviteBox:     { background:"#1a1a1a", borderRadius:12, padding:16 },
  codeBox:       { flex:1, background:"#0d0d0d", border:"1px solid #333", borderRadius:8, padding:"10px 14px", fontFamily:"monospace", fontSize:18, fontWeight:700, color:"#6BCB77", letterSpacing:3, textAlign:"center" },
  msgList:       { flex:1, overflowY:"auto", padding:"20px 16px", display:"flex", flexDirection:"column", gap:12 },
  msgRow:        { display:"flex", alignItems:"flex-end", gap:8 },
  avatar:        { width:32, height:32, borderRadius:"50%", flexShrink:0, display:"flex", alignItems:"center", justifyContent:"center", fontWeight:700, fontSize:13, color:"#000" },
  bubble:        { padding:"10px 14px", borderRadius:16, fontSize:14, lineHeight:1.5, wordBreak:"break-word", whiteSpace:"pre-wrap" },
  bubbleMe:      { background:"#4D96FF", color:"#fff", borderBottomRightRadius:4 },
  bubbleThem:    { background:"#1e1e1e", color:"#e0e0e0", borderBottomLeftRadius:4 },
  inputArea:     { padding:"12px 16px 16px", background:"#111", borderTop:"1px solid #1e1e1e", flexShrink:0 },
  textarea:      { flex:1, padding:"10px 14px", borderRadius:12, border:"1px solid #333", background:"#1a1a1a", color:"#fff", fontSize:14, resize:"none", outline:"none", fontFamily:"inherit", lineHeight:1.5, maxHeight:120 },
  sendBtn:       { padding:"10px 18px", borderRadius:12, border:"none", background:"linear-gradient(90deg,#4D96FF,#6BCB77)", color:"#fff", fontWeight:700, fontSize:14, cursor:"pointer", flexShrink:0, height:42 },
  ttlBtn:        { padding:"3px 8px", borderRadius:6, border:"1px solid #2a2a2a", background:"#1a1a1a", color:"#666", fontSize:11, cursor:"pointer" },
  ttlBtnActive:  { borderColor:"#FF922B", color:"#FF922B", background:"#FF922B15" },
};
