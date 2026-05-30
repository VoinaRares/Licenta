"use client";

import { useState, useEffect, useCallback } from "react";
import {
  handshake,
  storeObject,
  retrieveObject,
  rotateKeys,
  createUser,
  listObjects,
} from "./lib/api";
import {
  encryptForStore,
  encryptWithSessionKey,
  decryptFromRetrieve,
  isValidSessionKey,
} from "./lib/crypto";
import {
  getApiKey,
  setApiKey as saveApiKey,
  clearAll,
  getObjects,
  addObject,
  removeObject,
  mergeServerObjects,
  saveSessionKey,
  StoredObject,
} from "./lib/storage";

type StringMap = Record<string, string>;
type BoolMap = Record<string, boolean>;

interface SessionKeyAlert {
  objectId: string;
  keyHex: string;
}

export default function Dashboard() {
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [objects, setObjects] = useState<StoredObject[]>([]);
  const [loadingObjects, setLoadingObjects] = useState(false);

  // no-key view
  const [customApiKey, setCustomApiKey] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [apiKeyCopied, setApiKeyCopied] = useState(false);

  // store form
  const [plaintext, setPlaintext] = useState("");
  const [customKeyInput, setCustomKeyInput] = useState("");
  const [customKeyError, setCustomKeyError] = useState<string | null>(null);
  const [needsVerification, setNeedsVerification] = useState(false);
  const [storing, setStoring] = useState(false);
  const [storeError, setStoreError] = useState<string | null>(null);

  // session key popup — shown after auto-generate
  const [sessionKeyAlert, setSessionKeyAlert] = useState<SessionKeyAlert | null>(null);
  const [alertKeyCopied, setAlertKeyCopied] = useState(false);

  // per-object retrieval state
  const [fetchedCiphertext, setFetchedCiphertext] = useState<StringMap>({});
  const [fetching, setFetching] = useState<BoolMap>({});
  const [keyInput, setKeyInput] = useState<StringMap>({});
  const [decrypted, setDecrypted] = useState<StringMap>({});
  const [decryptError, setDecryptError] = useState<StringMap>({});
  const [showSessionKey, setShowSessionKey] = useState<BoolMap>({});

  // header
  const [showApiKey, setShowApiKey] = useState(false);
  const [rotateStatus, setRotateStatus] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);

  const syncObjects = useCallback(async (key: string) => {
    setLoadingObjects(true);
    try {
      const result = await listObjects(key);
      mergeServerObjects(result.objects);
    } catch {
      // non-fatal
    } finally {
      setObjects(getObjects());
      setLoadingObjects(false);
    }
  }, []);

  useEffect(() => {
    const key = getApiKey();
    if (key) {
      setApiKey(key);
      syncObjects(key);
    }
  }, [syncObjects]);

  function handleLogout() {
    clearAll();
    setApiKey(null);
    setObjects([]);
    setNewKey(null);
    setFetchedCiphertext({});
    setDecrypted({});
    setKeyInput({});
    setSessionKeyAlert(null);
  }

  async function handleCreate() {
    setCreating(true);
    setCreateError(null);
    try {
      const result = await createUser();
      saveApiKey(result.api_key);
      setNewKey(result.api_key);
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : "Failed to create account");
    } finally {
      setCreating(false);
    }
  }

  async function handleCopyNewApiKey() {
    if (!newKey) return;
    await navigator.clipboard.writeText(newKey);
    setApiKeyCopied(true);
    setTimeout(() => setApiKeyCopied(false), 2000);
  }

  function handleUseNewKey() {
    if (!newKey) return;
    setApiKey(newKey);
    syncObjects(newKey);
    setNewKey(null);
  }

  function handleLoadApiKey() {
    const trimmed = customApiKey.trim();
    if (!trimmed) return;
    saveApiKey(trimmed);
    setApiKey(trimmed);
    syncObjects(trimmed);
    setCustomApiKey("");
  }

  async function handleStore() {
    if (!apiKey || !plaintext.trim()) return;
    const providedKey = customKeyInput.trim();

    if (providedKey && !isValidSessionKey(providedKey)) {
      setCustomKeyError("Session key must be exactly 64 hex characters (32 bytes).");
      return;
    }

    setStoring(true);
    setStoreError(null);
    setCustomKeyError(null);

    try {
      let ciphertextB64: string;
      let sessionKeyHex: string;

      if (providedKey) {
        ciphertextB64 = await encryptWithSessionKey(providedKey, plaintext);
        sessionKeyHex = providedKey;
      } else {
        const hs = await handshake(apiKey);
        const result = await encryptForStore(hs.server_pubkey_b64, plaintext);
        ciphertextB64 = result.ciphertextB64;
        sessionKeyHex = result.sessionKeyHex;
      }

      const result = await storeObject(apiKey, ciphertextB64, needsVerification);

      const obj: StoredObject = {
        id: result.object_id,
        sessionKeyHex,
        storedAt: new Date().toISOString(),
        needsVerification,
      };
      addObject(obj);
      setObjects(getObjects());
      setPlaintext("");
      setCustomKeyInput("");
      setNeedsVerification(false);

      if (!providedKey) {
        setSessionKeyAlert({ objectId: result.object_id, keyHex: sessionKeyHex });
        setAlertKeyCopied(false);
      }
    } catch (e) {
      setStoreError(e instanceof Error ? e.message : "Store failed");
    } finally {
      setStoring(false);
    }
  }

  async function handleFetch(obj: StoredObject) {
    if (!apiKey) return;
    setFetching((prev) => ({ ...prev, [obj.id]: true }));
    setDecryptError((prev) => ({ ...prev, [obj.id]: "" }));
    try {
      const result = await retrieveObject(apiKey, obj.id);
      setFetchedCiphertext((prev) => ({ ...prev, [obj.id]: result.client_ciphertext_b64 }));
      if (obj.sessionKeyHex) {
        setKeyInput((prev) => ({ ...prev, [obj.id]: obj.sessionKeyHex! }));
      }
    } catch (e) {
      setDecryptError((prev) => ({
        ...prev,
        [obj.id]: e instanceof Error ? e.message : "Fetch failed",
      }));
    } finally {
      setFetching((prev) => ({ ...prev, [obj.id]: false }));
    }
  }

  async function handleDecrypt(obj: StoredObject) {
    const ciphertext = fetchedCiphertext[obj.id];
    const key = keyInput[obj.id]?.trim();
    if (!ciphertext || !key) return;
    setDecryptError((prev) => ({ ...prev, [obj.id]: "" }));
    try {
      const plain = await decryptFromRetrieve(ciphertext, key);
      setDecrypted((prev) => ({ ...prev, [obj.id]: plain }));
      if (!obj.sessionKeyHex) {
        saveSessionKey(obj.id, key);
        setObjects(getObjects());
      }
    } catch {
      setDecryptError((prev) => ({
        ...prev,
        [obj.id]: "Decryption failed — wrong session key?",
      }));
    }
  }

  function handleRemove(id: string) {
    removeObject(id);
    setObjects(getObjects());
    setFetchedCiphertext((prev) => { const n = { ...prev }; delete n[id]; return n; });
    setDecrypted((prev) => { const n = { ...prev }; delete n[id]; return n; });
    setKeyInput((prev) => { const n = { ...prev }; delete n[id]; return n; });
  }

  async function handleRotate() {
    if (!apiKey) return;
    setRotating(true);
    setRotateStatus(null);
    try {
      const result = await rotateKeys(apiKey);
      const rotatedCount = result.rotated?.length ?? 0;
      const failedCount = result.failed?.length ?? 0;
      setRotateStatus(
        `Rotated ${rotatedCount} object(s)${failedCount > 0 ? `, ${failedCount} failed` : ""}`
      );
    } catch (e) {
      setRotateStatus(e instanceof Error ? e.message : "Rotation failed");
    } finally {
      setRotating(false);
    }
  }

  // ── No API key ────────────────────────────────────────────────────────────
  if (!apiKey) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="bg-white border border-gray-300 rounded p-8 w-full max-w-md shadow-sm">
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">Secure Storage</h1>
          <p className="text-sm text-gray-700 mb-6">
            End-to-end encrypted storage backed by Shamir&apos;s Secret Sharing
            across distributed nodes. No single party ever holds your key.
          </p>

          {newKey ? (
            <>
              <p className="text-sm text-gray-700 mb-2">
                Account created. Copy your API key — it is shown only once and
                cannot be recovered.
              </p>
              <div className="bg-gray-100 border border-gray-300 rounded p-3 font-mono text-sm text-gray-900 break-all mb-4">
                {newKey}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleCopyNewApiKey}
                  className="flex-1 border border-gray-400 py-2 px-4 rounded text-sm text-gray-900 hover:bg-gray-100"
                >
                  {apiKeyCopied ? "Copied" : "Copy key"}
                </button>
                <button
                  onClick={handleUseNewKey}
                  className="flex-1 bg-black text-white py-2 px-4 rounded text-sm font-medium hover:bg-gray-800"
                >
                  Go to dashboard
                </button>
              </div>
            </>
          ) : (
            <>
              <button
                onClick={handleCreate}
                disabled={creating}
                className="w-full bg-black text-white py-2 px-4 rounded text-sm font-medium hover:bg-gray-800 disabled:opacity-50 mb-4"
              >
                {creating ? "Creating account..." : "Create new account"}
              </button>
              {createError && (
                <p className="text-red-600 text-sm mb-4">{createError}</p>
              )}
              <div className="flex items-center gap-3 mb-4">
                <div className="flex-1 border-t border-gray-300" />
                <span className="text-xs text-gray-600">or use existing key</span>
                <div className="flex-1 border-t border-gray-300" />
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Paste API key"
                  value={customApiKey}
                  onChange={(e) => setCustomApiKey(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLoadApiKey()}
                  className="flex-1 border border-gray-400 rounded px-3 py-2 text-sm text-gray-900 placeholder-gray-500"
                />
                <button
                  onClick={handleLoadApiKey}
                  className="border border-gray-400 rounded px-3 py-2 text-sm text-gray-900 hover:bg-gray-100"
                >
                  Use key
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

  // ── Dashboard ─────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gray-100">

      {/* Session key modal */}
      {sessionKeyAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white border border-gray-300 rounded shadow-lg w-full max-w-md mx-4 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-1">
              Save your session key
            </h2>
            <p className="text-sm text-gray-700 mb-1">
              Object <span className="font-mono font-medium">{sessionKeyAlert.objectId}</span> was
              stored successfully.
            </p>
            <p className="text-sm text-red-700 font-medium mb-3">
              This is the only copy of your session key. It is not stored on the
              server. If you close this dialog without saving it, you will not be
              able to decrypt this object after logging out.
            </p>
            <div className="bg-gray-100 border border-gray-300 rounded p-3 font-mono text-sm text-gray-900 break-all mb-4">
              {sessionKeyAlert.keyHex}
            </div>
            <div className="flex gap-2">
              <button
                onClick={async () => {
                  await navigator.clipboard.writeText(sessionKeyAlert.keyHex);
                  setAlertKeyCopied(true);
                  setTimeout(() => setAlertKeyCopied(false), 2000);
                }}
                className="flex-1 border border-gray-400 py-2 px-4 rounded text-sm text-gray-900 hover:bg-gray-100"
              >
                {alertKeyCopied ? "Copied" : "Copy key"}
              </button>
              <button
                onClick={() => setSessionKeyAlert(null)}
                className="flex-1 bg-black text-white py-2 px-4 rounded text-sm font-medium hover:bg-gray-800"
              >
                I have saved this key
              </button>
            </div>
          </div>
        </div>
      )}

      <header className="bg-white border-b border-gray-300 px-6 py-3 flex items-center justify-between shadow-sm">
        <span className="font-semibold text-sm text-gray-900">Secure Storage</span>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setShowApiKey(!showApiKey)}
            className="text-xs text-gray-700 hover:text-gray-900 font-mono"
          >
            API key: {showApiKey ? apiKey : `${apiKey.slice(0, 8)}...`}
          </button>
          <button
            onClick={handleLogout}
            className="text-xs text-gray-700 hover:text-gray-900"
          >
            Clear &amp; logout
          </button>
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-4 py-8 space-y-8">

        {/* Store */}
        <section className="bg-white border border-gray-300 rounded p-6 shadow-sm">
          <h2 className="font-semibold text-sm text-gray-900 mb-4">Store encrypted data</h2>
          <div className="space-y-3">
            <textarea
              placeholder="Enter text to encrypt and store..."
              value={plaintext}
              onChange={(e) => setPlaintext(e.target.value)}
              rows={4}
              className="w-full border border-gray-400 rounded px-3 py-2 text-sm text-gray-900 placeholder-gray-500 resize-none"
            />
            <div>
              <input
                type="text"
                placeholder="Session key (64 hex chars) — leave empty to auto-generate"
                value={customKeyInput}
                onChange={(e) => {
                  setCustomKeyInput(e.target.value);
                  setCustomKeyError(null);
                }}
                className="w-full border border-gray-400 rounded px-3 py-2 text-sm font-mono text-gray-900 placeholder-gray-500"
              />
              {customKeyError && (
                <p className="text-red-600 text-sm mt-1">{customKeyError}</p>
              )}
              <p className="text-xs text-gray-600 mt-1">
                If you provide a key, no popup will appear — you already know it.
                If left empty, a key is generated and shown once after storing.
              </p>
            </div>
            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={needsVerification}
                onChange={(e) => setNeedsVerification(e.target.checked)}
                className="mt-0.5 h-4 w-4 accent-black"
              />
              <span className="text-sm text-gray-900">
                Require additional verification before release
                <span className="block text-xs text-gray-600">
                  Marks this object so the server demands an extra signed
                  release token from an admin at retrieval time.
                </span>
              </span>
            </label>
            <button
              onClick={handleStore}
              disabled={storing || !plaintext.trim()}
              className="bg-black text-white py-2 px-4 rounded text-sm font-medium hover:bg-gray-800 disabled:opacity-50"
            >
              {storing ? "Encrypting and storing..." : "Encrypt and store"}
            </button>
            {storeError && <p className="text-red-600 text-sm">{storeError}</p>}
          </div>
        </section>

        {/* Object list */}
        <section className="bg-white border border-gray-300 rounded p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-sm text-gray-900">Stored objects</h2>
            <span className="text-xs text-gray-700 font-medium">
              {loadingObjects ? "Loading..." : `${objects.length} item(s)`}
            </span>
          </div>

          {objects.length === 0 ? (
            <p className="text-sm text-gray-700">
              {loadingObjects ? "Fetching objects from server..." : "No objects stored yet."}
            </p>
          ) : (
            <div className="space-y-4">
              {objects.map((obj) => {
                const hasLocalKey = !!obj.sessionKeyHex;
                const isFetching = fetching[obj.id];
                const hasCiphertext = !!fetchedCiphertext[obj.id];
                const isDecrypted = decrypted[obj.id] !== undefined;
                const currentKeyInput = keyInput[obj.id] ?? "";
                const err = decryptError[obj.id];

                return (
                  <div key={obj.id} className="border border-gray-300 rounded p-4 space-y-3">

                    {/* Header */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-sm font-medium text-gray-900">Object {obj.id}</p>
                          {obj.needsVerification && (
                            <span className="text-xs font-medium px-2 py-0.5 rounded border border-purple-300 bg-purple-50 text-purple-800">
                              Requires verification
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-600 mt-0.5">
                          {obj.storedAt
                            ? new Date(obj.storedAt).toLocaleString()
                            : "Stored on server"}
                          {!hasLocalKey && (
                            <span className="ml-2 text-amber-700 font-medium">
                              — no local session key
                            </span>
                          )}
                        </p>
                      </div>
                      <div className="flex gap-2 shrink-0">
                        {!hasCiphertext && (
                          <button
                            onClick={() => handleFetch(obj)}
                            disabled={isFetching}
                            className="text-xs border border-gray-400 rounded px-2 py-1 text-gray-900 hover:bg-gray-100 disabled:opacity-50"
                          >
                            {isFetching ? "Fetching..." : "Retrieve from server"}
                          </button>
                        )}
                        <button
                          onClick={() => handleRemove(obj.id)}
                          className="text-xs border border-gray-400 rounded px-2 py-1 text-gray-700 hover:bg-gray-100"
                        >
                          Remove from list
                        </button>
                      </div>
                    </div>

                    {/* Session key — visible for objects with a stored key */}
                    {hasLocalKey && (
                      <div className="border-t border-gray-200 pt-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-gray-700 font-medium">Session key</span>
                          <div className="flex gap-2">
                            <button
                              onClick={() =>
                                setShowSessionKey((prev) => ({ ...prev, [obj.id]: !prev[obj.id] }))
                              }
                              className="text-xs text-gray-700 hover:text-gray-900 underline"
                            >
                              {showSessionKey[obj.id] ? "Hide" : "Show"}
                            </button>
                            {showSessionKey[obj.id] && (
                              <button
                                onClick={() => navigator.clipboard.writeText(obj.sessionKeyHex!)}
                                className="text-xs text-gray-700 hover:text-gray-900 underline"
                              >
                                Copy
                              </button>
                            )}
                          </div>
                        </div>
                        {showSessionKey[obj.id] && (
                          <>
                            <div className="mt-1 bg-gray-100 border border-gray-300 rounded p-2 font-mono text-xs text-gray-900 break-all">
                              {obj.sessionKeyHex}
                            </div>
                            <p className="text-xs text-gray-600 mt-1">
                              Save this key. It is the only way to decrypt this object if your browser data is cleared.
                            </p>
                          </>
                        )}
                      </div>
                    )}

                    {/* Decrypt step */}
                    {hasCiphertext && !isDecrypted && (
                      <div className="border-t border-gray-200 pt-3 space-y-2">
                        <p className="text-xs text-gray-700 font-medium">
                          Encrypted blob retrieved. Enter the session key to decrypt.
                        </p>
                        <div className="flex gap-2">
                          <input
                            type="text"
                            placeholder="Session key (hex)"
                            value={currentKeyInput}
                            onChange={(e) =>
                              setKeyInput((prev) => ({ ...prev, [obj.id]: e.target.value }))
                            }
                            className="flex-1 border border-gray-400 rounded px-3 py-2 text-sm font-mono text-gray-900 placeholder-gray-500"
                          />
                          <button
                            onClick={() => handleDecrypt(obj)}
                            disabled={!currentKeyInput.trim()}
                            className="border border-gray-400 rounded px-3 py-2 text-sm text-gray-900 hover:bg-gray-100 disabled:opacity-50"
                          >
                            Decrypt
                          </button>
                        </div>
                        {err && <p className="text-red-600 text-sm">{err}</p>}
                      </div>
                    )}

                    {/* Decrypted content */}
                    {isDecrypted && (
                      <div className="border-t border-gray-200 pt-3">
                        <p className="text-xs text-gray-700 font-medium mb-1">Decrypted content:</p>
                        <pre className="text-sm bg-gray-100 border border-gray-300 rounded p-3 whitespace-pre-wrap break-all text-gray-900">
                          {decrypted[obj.id]}
                        </pre>
                      </div>
                    )}

                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* Key rotation */}
        <section className="bg-white border border-gray-300 rounded p-6 shadow-sm">
          <h2 className="font-semibold text-sm text-gray-900 mb-1">Key rotation</h2>
          <p className="text-sm text-gray-700 mb-4">
            Re-encrypts all stored objects on the server with new Shamir shares.
            Your local session keys are unaffected.
          </p>
          <button
            onClick={handleRotate}
            disabled={rotating}
            className="border border-gray-400 py-2 px-4 rounded text-sm text-gray-900 hover:bg-gray-100 disabled:opacity-50"
          >
            {rotating ? "Rotating keys..." : "Rotate server-side keys"}
          </button>
          {rotateStatus && (
            <p className="mt-2 text-sm text-gray-800">{rotateStatus}</p>
          )}
        </section>

      </main>
    </div>
  );
}
