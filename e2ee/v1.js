/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *           This script is provides the privacy features           *
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
const CHANNEL = "users-e2ee"

const ENVELOPE = "e1."
const WRAPPED = "x1."
const WRAP_INFO = "webfluid-mobile-x1"
const SESSION_INFO = "users-e2ee-session"
const QR_SCHEME = "users-sdk"

const KEY_LENGTH = 32
const NONCE_LENGTH = 12
const TAG_LENGTH = 16

const encoder = new TextEncoder()
const decoder = new TextDecoder("utf-8", { fatal: true })
const channel = "BroadcastChannel" in globalThis ? new BroadcastChannel(CHANNEL) : null

let accountKey = null
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


function database() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DATABASE, 1)
        request.onupgradeneeded = () => request.result.createObjectStore(STORE)
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
    })
}

async function transaction(mode, work) {
    const db = await database()
    try {
        return await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE, mode)
            const request = work(tx.objectStore(STORE))
            tx.oncomplete = () => resolve(request?.result)
            tx.onerror = () => reject(tx.error)
            tx.onabort = () => reject(tx.error)
        })
    } finally {
        db.close()
    }
}

const read = name => transaction("readonly", store => store.get(name))
const write = (name, value) => transaction("readwrite", store => store.put(value, name))
const clear = () => transaction("readwrite", store => store.clear())


async function importAccountKey(raw) {
    if (raw.length !== KEY_LENGTH) throw new Error("Invalid account key.")
    try {
        return await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
    } finally {
        raw.fill(0)
    }
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
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH))
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
    support ??= subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])
        .then(() => typeof indexedDB !== "undefined")
        .catch(() => false)
    return support
}

export function ready() {
    return accountKey !== null
}

export function isEnvelope(value) {
    if (typeof value !== "string" || !value.startsWith(ENVELOPE)) return false
    try {
        return decode(value.slice(ENVELOPE.length)).length >= NONCE_LENGTH + TAG_LENGTH
    } catch {
        return false
    }
}

export async function reset() {
    accountKey = null
    await clear().catch(() => null)
    channel?.postMessage("reset")
    globalThis.dispatchEvent(new Event("users:e2ee-reset"))
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

export async function encrypt(text) {
    if (!accountKey) throw new Error("The account key is locked.")
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH))
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
    globalThis.dispatchEvent(new Event("users:e2ee-reset"))
})

window.wf.adt.users = {
    ...window.wf.adt.users,
    e2ee: { hash, supported, ready, isEnvelope, reset, begin, link, accept, unlock, encrypt, decrypt }
}
window.dispatchEvent(new Event("users:e2ee"))

guard().catch(() => null)
