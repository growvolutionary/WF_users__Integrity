/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *            This script provides the privacy features             *
 *    of the WebFluid "users" Additive. To keep your application    *
 *    transparent and secure, you should not edit or change it's    *
 *     content by yourself. Additionaly we highly recommend to      *
 *    add the "peering" Additive to your application and to not     *
 *          remove the "users" Additives peering features.          *
 *                                                                  *
 ********************************************************************/

const subtle = globalThis.crypto.subtle

const SOURCE = import.meta.url
const PREFIX = new URL(SOURCE).pathname.replace(/\/static\/js\/e2ee\.js$/, "")

const DATABASE = "users-e2ee"
const STORE = "keystore"
const VAULT = "vault"
const CHANNEL = "users-e2ee"

const ENVELOPE = "e1."
const WRAPPED = "x1."
const WRAP_INFO = "webfluid-mobile-x1"
const SESSION_INFO = "users-e2ee-session"
const RECOVERY_SALT = "users-recovery"
const RECOVERY_INFO = "users-recovery-signing-v1"
const COMMITMENT_SALT = "users-commitment"
const COMMITMENT_INFO = "users-commitment-salt-v1"
const KEYLOG_SUBJECT = "wf-keylog-v1:subject"
const KEYLOG_AUTHORITY = "wf-keylog-v1:authority"
const COMMIT_CONTEXT = "users-recovery-commit-v1"
const QR_SCHEME = "users-sdk"
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])

const KEY_LENGTH = 32
const NONCE_LENGTH = 12
const TAG_LENGTH = 16
const SALT_LENGTH = 16
const GENESIS = "0".repeat(64)

const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true })
const channel = "BroadcastChannel" in globalThis ? new BroadcastChannel(CHANNEL) : null

let accountKey = null
let commitmentSalt = null
let heldRecovery = null
let pendingRotation = null
let scriptHash = null
let support = null


function encode(bytes) {
    let binary = ""
    for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function decode(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
        throw new TypeError("Malformed base64url value.")
    }
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4))
    return Uint8Array.from(binary, char => char.charCodeAt(0))
}

function concat(...parts) {
    const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0))
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

function hex(buffer) {
    return Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("")
}

function random(length) {
    return crypto.getRandomValues(new Uint8Array(length))
}


export function canonical(value) {
    if (value === null) return "null"
    if (value === true) return "true"
    if (value === false) return "false"
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) throw new TypeError("Only safe integers are canonical.")
        return String(value)
    }
    if (typeof value === "string") {
        if (/[\ud800-\udfff]/.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ""))) {
            throw new TypeError("Lone surrogates are not canonical.")
        }
        return JSON.stringify(value)
    }
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`
    if (typeof value === "object") {
        const keys = Object.keys(value).filter(key => value[key] !== undefined).sort()
        for (const key of keys) {
            if (!/^[\x20-\x7e]+$/.test(key)) throw new TypeError("Object keys must be printable ASCII.")
        }
        return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
    }
    throw new TypeError("Value cannot be canonicalized.")
}

async function sha256(text) {
    return hex(await subtle.digest("SHA-256", encoder.encode(text)))
}

export function formatRecovery(bytes) {
    let out = "", buffer = 0, bits = 0
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte
        bits += 8
        while (bits >= 5) {
            bits -= 5
            out += BASE32[(buffer >> bits) & 31]
        }
        buffer &= (1 << bits) - 1
    }
    if (bits > 0) out += BASE32[(buffer << (5 - bits)) & 31]
    return out.match(/.{1,4}/g).join("-")
}

export function parseRecovery(text) {
    const cleaned = String(text || "").toUpperCase().replace(/[\s-]/g, "")
    if (!cleaned || [...cleaned].some(char => !BASE32.includes(char))) return null
    const out = []
    let buffer = 0, bits = 0
    for (const char of cleaned) {
        buffer = (buffer << 5) | BASE32.indexOf(char)
        bits += 5
        if (bits >= 8) {
            bits -= 8
            out.push((buffer >> bits) & 255)
            buffer &= (1 << bits) - 1
        }
    }
    return out.length === KEY_LENGTH ? Uint8Array.from(out) : null
}


function database() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DATABASE, 2)
        request.onupgradeneeded = () => {
            const db = request.result
            if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE)
            if (!db.objectStoreNames.contains(VAULT)) db.createObjectStore(VAULT)
        }
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
    })
}

async function transaction(store, mode, work) {
    const db = await database()
    try {
        return await new Promise((resolve, reject) => {
            const tx = db.transaction(store, mode)
            const request = work(tx.objectStore(store))
            tx.oncomplete = () => resolve(request?.result)
            tx.onerror = () => reject(tx.error)
            tx.onabort = () => reject(tx.error)
        })
    } finally {
        db.close()
    }
}

const read = name => transaction(STORE, "readonly", store => store.get(name))
const write = (name, value) => transaction(STORE, "readwrite", store => store.put(value, name))
const clear = () => transaction(STORE, "readwrite", store => store.clear())
const vaultRead = name => transaction(VAULT, "readonly", store => store.get(name))
const vaultWrite = (name, value) => transaction(VAULT, "readwrite", store => store.put(value, name))
const vaultDelete = name => transaction(VAULT, "readwrite", store => store.delete(name))


async function hkdf(raw, salt, info, bits) {
    const material = await subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"])
    return new Uint8Array(await subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: encoder.encode(salt), info: encoder.encode(info) }, material, bits
    ))
}

async function importAccountKey(raw) {
    if (raw.length !== KEY_LENGTH) throw new Error("Invalid account key.")
    try {
        commitmentSalt = encode(await hkdf(raw, COMMITMENT_SALT, COMMITMENT_INFO, SALT_LENGTH * 8))
        return await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
    } finally {
        raw.fill(0)
    }
}

async function wrapTo(recipient, data) {
    const ephemeral = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])
    const epk = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey))
    const remote = await subtle.importKey("raw", decode(recipient), { name: "X25519" }, false, [])
    const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: remote }, ephemeral.privateKey, 256))
    if (shared.every(byte => byte === 0)) throw new Error("Weak key agreement.")
    const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"])
    shared.fill(0)
    const key = await subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: concat(epk, decode(recipient)), info: encoder.encode(WRAP_INFO) },
        material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    )
    const nonce = random(NONCE_LENGTH)
    const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data))
    return WRAPPED + encode(concat(epk, nonce, sealed))
}

async function openWrapped(pair, envelope) {
    if (typeof envelope !== "string" || !envelope.startsWith(WRAPPED)) throw new Error("Not a wrapped value.")
    const raw = decode(envelope.slice(WRAPPED.length))
    if (raw.length < KEY_LENGTH + NONCE_LENGTH + TAG_LENGTH) throw new Error("Wrapped value is too short.")

    const epk = raw.slice(0, KEY_LENGTH)
    const nonce = raw.slice(KEY_LENGTH, KEY_LENGTH + NONCE_LENGTH)
    const remote = await subtle.importKey("raw", epk, { name: "X25519" }, false, [])
    const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: remote }, pair.privateKey, 256))
    if (shared.every(byte => byte === 0)) throw new Error("Weak key agreement.")

    const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"])
    shared.fill(0)
    const key = await subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: concat(epk, decode(pair.publicKey)), info: encoder.encode(WRAP_INFO) },
        material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    )
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, raw.slice(KEY_LENGTH + NONCE_LENGTH)))
}

async function sealBytes(key, data) {
    const aes = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"])
    const nonce = random(NONCE_LENGTH)
    const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, data))
    return ENVELOPE + encode(concat(nonce, sealed))
}

async function openBytes(key, envelope) {
    if (!isEnvelope(envelope)) throw new TypeError("Not a sealed value.")
    const raw = decode(envelope.slice(ENVELOPE.length))
    const aes = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"])
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, NONCE_LENGTH) }, aes, raw.slice(NONCE_LENGTH)))
}

async function recoverySigner(secret) {
    const seed = await hkdf(secret, RECOVERY_SALT, RECOVERY_INFO, 256)
    try {
        const exportable = await subtle.importKey("pkcs8", concat(PKCS8_ED25519, seed), { name: "Ed25519" }, true, ["sign"])
        const publicKey = (await subtle.exportKey("jwk", exportable)).x
        const privateKey = await subtle.importKey("pkcs8", concat(PKCS8_ED25519, seed), { name: "Ed25519" }, false, ["sign"])
        return { publicKey, privateKey }
    } finally {
        seed.fill(0)
    }
}

async function sign(signer, context, value) {
    const message = encoder.encode(`${context}\n${canonical(value)}`)
    return encode(await subtle.sign({ name: "Ed25519" }, signer.privateKey, message))
}

function statement(account, state, type, authority, keys) {
    return {
        v: 1, account, seq: state.seq + 1, prev: state.head || GENESIS, type, authority, keys,
        ts: Math.floor(Date.now() / 1000)
    }
}

function envelopeOf(data, subject, authority) {
    return { protocol: "wf-keylog-v1", statement: data, signatures: { subject, authority } }
}

async function next(state, data) {
    return { seq: data.seq, head: await sha256(canonical(data)) }
}

async function sessionKey(share, handshake, usage) {
    const material = await subtle.importKey("raw", decode(share), "HKDF", false, ["deriveKey"])
    return subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: encoder.encode(handshake), info: encoder.encode(SESSION_INFO) },
        material, { name: "AES-GCM", length: 256 }, false, [usage]
    )
}

function binding(user, handshake) {
    return encoder.encode(`${user}\n${handshake}`)
}

async function sealForSession(share, handshake, user, payload) {
    const nonce = random(NONCE_LENGTH)
    const sealed = await subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: binding(user, handshake) },
        await sessionKey(share, handshake, "encrypt"), encoder.encode(payload)
    )
    return encode(concat(nonce, new Uint8Array(sealed)))
}

async function openForSession(share, handshake, user, sealed) {
    const raw = decode(sealed)
    const plain = await subtle.decrypt(
        { name: "AES-GCM", iv: raw.slice(0, NONCE_LENGTH), additionalData: binding(user, handshake) },
        await sessionKey(share, handshake, "decrypt"), raw.slice(NONCE_LENGTH)
    )
    return decoder.decode(plain)
}

async function newBrowserKey(user) {
    const pair = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
    const publicKey = encode(await subtle.exportKey("raw", pair.publicKey))
    await vaultWrite(String(user), { privateKey: pair.privateKey, publicKey, created: Date.now() })
    return publicKey
}


export function hash() {
    scriptHash ??= fetch(SOURCE, { cache: "force-cache", credentials: "same-origin" })
        .then(response => {
            if (!response.ok) throw new Error(`Loading ${SOURCE} answered HTTP ${response.status}.`)
            return response.arrayBuffer()
        })
        .then(source => subtle.digest("SHA-256", source))
        .then(hex)
        .catch(error => {
            scriptHash = null
            throw error
        })
    return scriptHash
}

export function supported() {
    support ??= Promise.all([
        subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]),
        subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])
    ]).then(() => typeof indexedDB !== "undefined").catch(() => false)
    return support
}

export function ready() {
    return accountKey !== null
}

export function salt() {
    return commitmentSalt
}

export function isEnvelope(value) {
    if (typeof value !== "string" || !value.startsWith(ENVELOPE)) return false
    try {
        return decode(value.slice(ENVELOPE.length)).length >= NONCE_LENGTH + TAG_LENGTH
    } catch {
        return false
    }
}

export async function commitment(value) {
    if (value === null || value === undefined) return null
    if (!commitmentSalt) throw new Error("The account key is locked.")
    if (Number.isSafeInteger(value)) return value
    return "c1:" + hex(await subtle.digest("SHA-256", concat(decode(commitmentSalt), Uint8Array.of(0), encoder.encode(String(value)))))
}

export async function reset() {
    accountKey = null
    commitmentSalt = null
    heldRecovery?.fill(0)
    heldRecovery = null
    pendingRotation = null
    await clear().catch(() => null)
    channel?.postMessage("reset")
    globalThis.dispatchEvent(new Event("users:e2ee-reset"))
}

export async function forget(user) {
    await vaultDelete(String(user)).catch(() => null)
    await reset()
}

export async function begin() {
    if (!await supported()) throw new Error("This browser cannot run the handshake.")
    await reset()

    const pair = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
    const key = encode(await subtle.exportKey("raw", pair.publicKey))
    await write("pair", { privateKey: pair.privateKey, publicKey: key, created: Date.now() })
    return { key, hash: await hash() }
}

export function link({ signature, origin, handshake, key, hash }) {
    const query = new URLSearchParams({ v: "1", sig: signature, origin, id: handshake, hash, key })
    return `${QR_SCHEME}://handshake?${query}`
}

export async function accept({ payload, share, handshake, user, expires }) {
    const pair = await read("pair")
    if (!pair || !payload || !share) {
        await reset()
        return false
    }

    try {
        accountKey = await importAccountKey(await openWrapped(pair, payload))
        await write("account", {
            handshake, user,
            sealed: await sealForSession(share, handshake, user, payload),
            expires: Date.now() + expires * 1000
        })
        return true
    } catch {
        await reset()
        return false
    }
}

export async function unlock({ share, handshake, user }) {
    if (accountKey && await read("account").then(record => record?.handshake === handshake).catch(() => false)) {
        return true
    }
    accountKey = null

    try {
        const [record, pair] = [await read("account"), await read("pair")]
        if (!share || !record || !pair || record.handshake !== handshake || record.user !== user
            || record.expires < Date.now()) {
            throw new Error("The keystore does not belong to this session.")
        }

        const payload = await openForSession(share, handshake, user, record.sealed)
        accountKey = await importAccountKey(await openWrapped(pair, payload))
        return true
    } catch {
        await reset()
        return false
    }
}

export async function vaultKey(user) {
    const entry = await vaultRead(String(user)).catch(() => null)
    return entry?.publicKey ?? null
}

export async function unlockVault({ user, wrapped }) {
    const entry = await vaultRead(String(user)).catch(() => null)
    if (!entry || !wrapped) return false
    try {
        accountKey = await importAccountKey(await openWrapped(entry, wrapped))
        return true
    } catch {
        accountKey = null
        commitmentSalt = null
        return false
    }
}

export async function enrol({ user, account, state }) {
    if (!await supported()) throw new Error("This browser cannot hold the account key.")
    if (state.seq !== 0 && state.recovery) throw new Error("The account already has a recovery key.")

    const key = random(KEY_LENGTH)
    const secret = random(KEY_LENGTH)
    try {
        const signer = await recoverySigner(secret)
        const browser = await newBrowserKey(user)
        const recovery = await sealBytes(secret, key)
        const wrapped = await wrapTo(browser, key)

        const first = statement(account, state, "recovery.set", "self", { recovery: signer.publicKey })
        const second = statement(account, await next(state, first), "browser.bind", "recovery", { enc: browser })
        const keylog = [
            envelopeOf(first, await sign(signer, KEYLOG_SUBJECT, first), null),
            envelopeOf(second, null, await sign(signer, KEYLOG_AUTHORITY, second))
        ]

        accountKey = await importAccountKey(key.slice())
        return { recoveryKey: formatRecovery(secret), recovery, browser: { key: browser, wrapped }, keylog, salt: commitmentSalt }
    } finally {
        key.fill(0)
        secret.fill(0)
    }
}

export async function recover({ user, account, state, recoveryKey, recovery }) {
    const secret = parseRecovery(recoveryKey)
    if (!secret) throw new Error("INVALID_RECOVERY_KEY")
    let key
    try {
        key = await openBytes(secret, recovery)
    } catch {
        secret.fill(0)
        throw new Error("INVALID_RECOVERY_KEY")
    }
    try {
        const signer = await recoverySigner(secret)
        if (state.recovery && state.recovery !== signer.publicKey) throw new Error("RECOVERY_KEY_NOT_ANCHORED")
        const browser = await newBrowserKey(user)
        const wrapped = await wrapTo(browser, key)
        const data = statement(account, state, "browser.bind", "recovery", { enc: browser })
        heldRecovery?.fill(0)
        heldRecovery = secret
        accountKey = await importAccountKey(key.slice())
        return {
            browser: { key: browser, wrapped, keylog: envelopeOf(data, null, await sign(signer, KEYLOG_AUTHORITY, data)) },
            salt: commitmentSalt
        }
    } finally {
        key.fill(0)
    }
}

export async function hold({ state, recoveryKey, recovery }) {
    const secret = parseRecovery(recoveryKey)
    if (!secret) throw new Error("INVALID_RECOVERY_KEY")
    try {
        (await openBytes(secret, recovery)).fill(0)
    } catch {
        secret.fill(0)
        throw new Error("INVALID_RECOVERY_KEY")
    }
    const signer = await recoverySigner(secret)
    if (state.recovery && state.recovery !== signer.publicKey) {
        secret.fill(0)
        throw new Error("RECOVERY_KEY_NOT_ANCHORED")
    }
    heldRecovery?.fill(0)
    heldRecovery = secret
    return true
}

export async function rotation({ account, state, recovery }) {
    if (!heldRecovery) throw new Error("The current recovery key is not available.")
    const key = await openBytes(heldRecovery, recovery)
    const fresh = random(KEY_LENGTH)
    try {
        const current = await recoverySigner(heldRecovery)
        const next = await recoverySigner(fresh)
        const data = statement(account, state, "recovery.set", "recovery", { recovery: next.publicKey })
        const id = encode(random(16))
        pendingRotation = { id, signer: next }
        return {
            rotation: id,
            recovery: await sealBytes(fresh, key),
            keylog: envelopeOf(data, await sign(next, KEYLOG_SUBJECT, data), await sign(current, KEYLOG_AUTHORITY, data)),
            recoveryKey: formatRecovery(fresh)
        }
    } finally {
        key.fill(0)
        fresh.fill(0)
    }
}

export async function confirmRotation({ account, rotation, version }) {
    if (!pendingRotation || pendingRotation.id !== rotation) throw new Error("Unknown rotation.")
    return sign(pendingRotation.signer, COMMIT_CONTEXT, { ctx: COMMIT_CONTEXT, account, rotation, version })
}

export function settleRotation() {
    heldRecovery?.fill(0)
    heldRecovery = null
    pendingRotation = null
}

export async function encrypt(text) {
    if (!accountKey) throw new Error("The account key is locked.")
    const nonce = random(NONCE_LENGTH)
    const sealed = await subtle.encrypt({ name: "AES-GCM", iv: nonce }, accountKey, encoder.encode(text))
    return ENVELOPE + encode(concat(nonce, new Uint8Array(sealed)))
}

export async function decrypt(envelope) {
    if (!accountKey) throw new Error("The account key is locked.")
    if (!isEnvelope(envelope)) throw new TypeError("Not a sealed value.")
    const raw = decode(envelope.slice(ENVELOPE.length))
    const plain = await subtle.decrypt(
        { name: "AES-GCM", iv: raw.slice(0, NONCE_LENGTH) }, accountKey, raw.slice(NONCE_LENGTH)
    )
    return decoder.decode(plain)
}


async function guard() {
    const record = await read("account").catch(() => null)
    if (!record) return
    if (record.expires < Date.now()) return reset()

    const response = await fetch(`${PREFIX}/api/v1/mobile/session`, { credentials: "same-origin" })
        .catch(() => null)
    if (!response || response.status === 429 || response.status >= 500) return

    const state = response.ok ? await response.json().catch(() => null) : null
    if (!state?.share || state.handshake !== record.handshake || state.user_id !== record.user) await reset()
}

channel?.addEventListener("message", event => {
    if (event.data !== "reset") return
    accountKey = null
    commitmentSalt = null
    globalThis.dispatchEvent(new Event("users:e2ee-reset"))
})

window.wf.adt.users = {
    ...window.wf.adt.users,
    e2ee: {
        hash, supported, ready, salt, isEnvelope, commitment, reset, forget, begin, link, accept, unlock,
        vaultKey, unlockVault, enrol, recover, hold, rotation, confirmRotation, settleRotation, encrypt, decrypt,
        canonical, formatRecovery, parseRecovery
    }
}
window.dispatchEvent(new Event("users:e2ee"))

guard().catch(() => null)
