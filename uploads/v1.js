/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *     This script encrypts the uploads of the WebFluid "users"     *
 *      Additive on your device and opens the public pools of       *
 *      its accounts. To keep your application transparent and      *
 *       secure, you should not edit or change its content by       *
 *      yourself. Additionally we highly recommend to add the       *
 *     "peering" Additive to your application and to not remove     *
 *             the "users" Additive's peering features.             *
 *                                                                  *
 ********************************************************************/

import * as vodozemac from "../vendor/vodozemac/0.1.0/vodozemac_bg.js"

const SOURCE = import.meta.url
const PREFIX = new URL(SOURCE).pathname.replace(/\/static\/js\/uploads\.js$/, "")
const API = `${PREFIX}/api/v1`
const FILES = `${API}/uploads/`
const FORMAT = "wf-file-v1"
const POOL = "users-pool-v1"
const ROOM = "users-pool-room-v1"
const POOL_MESSAGE = "users-pool"
const SIGNING = "users-olm-signing-v1"
const EVERYONE = "everyone"
const WASM_SHA256 = "5b3a606864bbcfe31f4e91f12e73b659c494f6d13c36cb6e1ec94dce992410fd"
const LOADED = Symbol.for("wf.users.vodozemac")
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
const POOL_TTL = 60000
const PLAIN = "plain"
const ENCRYPT = "encrypt"
const DECRYPT = "decrypt"
const ROOM_MESSAGES = 100
const ROOM_AGE = 7 * 24 * 60 * 60 * 1000
const KNOWN_ROOMS = 64
const INBOUND_CACHE = 32
const OUTBOUND_STORE = "users-pool-outbound:"
const KNOWN_STORE = "users-pool-rooms:"
const TIMEOUT = 10000

const subtle = globalThis.crypto.subtle
const encoder = new TextEncoder()
const MAGIC = encoder.encode(FORMAT)

const pools = new Map()
const joining = new Map()
const opened = new Map()
const inbound = new Map()
const rooms = new Map()
let state = null
let fulfilling = null
let recrypting = null


export class UploadError extends Error {
    constructor(code) {
        super(code)
        this.code = code
    }
}

export function secure() {
    return !!globalThis.isSecureContext && !!subtle
}

function requireSecure() {
    if (!secure()) throw new UploadError("INSECURE_CONTEXT")
}

function concat(...parts) {
    const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

function b64url(bytes) {
    let binary = ""
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_")
}

function fromB64url(text) {
    const value = String(text).replace(/-/g, "+").replace(/_/g, "/")
    const binary = atob(value + "=".repeat((4 - value.length % 4) % 4))
    return Uint8Array.from(binary, char => char.charCodeAt(0))
}

async function hex(bytes) {
    return Array.from(new Uint8Array(await subtle.digest("SHA-256", bytes)), byte => byte.toString(16).padStart(2, "0")).join("")
}

async function fingerprint(key) {
    return b64url(new Uint8Array(await subtle.digest("SHA-256", fromB64url(key))).slice(0, 16))
}

function readStore(key) {
    try {
        const raw = localStorage.getItem(key)
        return raw ? JSON.parse(raw) : null
    } catch {
        return null
    }
}

function writeStore(key, value) {
    try {
        if (value === null) localStorage.removeItem(key)
        else localStorage.setItem(key, JSON.stringify(value))
    } catch {}
}

function waitFor(read, event) {
    const found = read()
    if (found) return Promise.resolve(found)
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new UploadError("E2EE_UNAVAILABLE")), TIMEOUT)
        window.addEventListener(event, () => {
            clearTimeout(timer)
            resolve(read())
        }, { once: true })
    })
}

const e2ee = () => waitFor(() => window.wf?.adt?.users?.e2ee, "users:e2ee")

function csrf() {
    const match = document.cookie.split("; ").find(item => item.startsWith("csrf_token="))
    return match ? decodeURIComponent(match.slice("csrf_token=".length)) : ""
}

async function json(path, init = {}) {
    const headers = new Headers(init.headers)
    if (init.method && init.method !== "GET") headers.set("X-CSRF-Token", csrf())
    if (init.body && typeof init.body === "string") headers.set("Content-Type", "application/json")
    const response = await fetch(path, { credentials: "same-origin", ...init, headers })
    const data = await response.json().catch(() => null)
    if (!response.ok) throw new UploadError(data?.detail ?? `HTTP_${response.status}`)
    return data
}

export function transfer(method, url, body, { onProgress, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const request = new XMLHttpRequest()
        request.open(method, url)
        request.withCredentials = true
        request.setRequestHeader("X-CSRF-Token", csrf())
        for (const [name, value] of Object.entries(headers)) request.setRequestHeader(name, value)
        request.responseType = "json"
        if (onProgress) {
            request.upload.onprogress = event => {
                if (event.lengthComputable) onProgress(event.loaded / event.total)
            }
        }
        request.onload = () => {
            if (request.status >= 200 && request.status < 300) {
                onProgress?.(1)
                resolve(request.response)
            } else {
                reject(new UploadError(request.response?.detail ?? `HTTP_${request.status}`))
            }
        }
        request.onerror = () => reject(new UploadError("NETWORK_ERROR"))
        request.send(body)
    })
}

export function load(wasm) {
    requireSecure()
    globalThis[LOADED] ??= (async () => {
        const bytes = wasm ?? await fetch(new URL("../vendor/vodozemac/0.1.0/vodozemac_bg.wasm", SOURCE),
            { credentials: "same-origin" }).then(response => {
            if (!response.ok) throw new UploadError("CRYPTO_UNAVAILABLE")
            return response.arrayBuffer()
        })
        if (await hex(bytes) !== WASM_SHA256) throw new UploadError("CRYPTO_MISMATCH")
        const { instance } = await WebAssembly.instantiate(bytes, { "./vodozemac_bg.js": vodozemac })
        vodozemac.__wbg_set_wasm(instance.exports)
        instance.exports.__wbindgen_start()
        return vodozemac
    })().catch(error => {
        delete globalThis[LOADED]
        throw error
    })
    return globalThis[LOADED]
}

export async function encryptFile(blob, { name, mime } = {}) {
    requireSecure()
    const key = globalThis.crypto.getRandomValues(new Uint8Array(32))
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const plain = new Uint8Array(await blob.arrayBuffer())
    const aes = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"])
    const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: MAGIC }, aes, plain))
    return {
        cipher: new Blob([MAGIC, sealed], { type: "application/octet-stream" }),
        key: {
            v: 1, alg: "A256GCM", key: b64url(key), iv: b64url(iv), size: plain.length,
            mime: mime || blob.type || "application/octet-stream", name: name ?? blob.name ?? null
        }
    }
}

export async function decryptFile(data, key) {
    requireSecure()
    if (key?.v !== 1 || key.alg !== "A256GCM") throw new UploadError("UNKNOWN_FORMAT")
    const bytes = new Uint8Array(data instanceof Blob ? await data.arrayBuffer() : data)
    if (bytes.length < MAGIC.length + 16 || !MAGIC.every((byte, index) => bytes[index] === byte)) {
        throw new UploadError("UNKNOWN_FORMAT")
    }
    const aes = await subtle.importKey("raw", fromB64url(key.key), { name: "AES-GCM" }, false, ["decrypt"])
    const plain = await subtle.decrypt({ name: "AES-GCM", iv: fromB64url(key.iv), additionalData: MAGIC }, aes,
        bytes.slice(MAGIC.length)).catch(() => {
        throw new UploadError("DECRYPTION_FAILED")
    })
    return new Blob([plain], { type: key.mime || "application/octet-stream" })
}

const UNAVAILABLE = { available: false, encrypted: null, private: false, audiences: [EVERYONE] }

export async function available({ fresh = false } = {}) {
    if (fresh) state = null
    state ??= fetch(`${API}/upload/available`, { credentials: "same-origin" })
        .then(response => response.ok ? response.json() : UNAVAILABLE)
        .catch(() => {
            state = null
            return UNAVAILABLE
        })
    return state
}

export async function list() {
    return await json(`${API}/uploads`)
}

export async function upload(files, { onProgress } = {}) {
    const chosen = Array.from(files)
    const { encrypted } = await available({ fresh: true })
    if (encrypted === null) throw new UploadError("UNAUTHORIZED")
    const form = new FormData()
    if (encrypted) {
        const crypto = await e2ee()
        if (!crypto.ready()) throw new UploadError("BROWSER_LOCKED")
        for (const file of chosen) {
            const { cipher, key } = await encryptFile(file)
            form.append("files", cipher, file.name)
            form.append("keys", await crypto.encrypt(JSON.stringify(key)))
            form.append("types", key.mime)
        }
    } else {
        for (const file of chosen) form.append("files", file, file.name)
    }
    const answer = await transfer("POST", `${API}/upload`, form, { onProgress })
    if (encrypted) await fulfil().catch(() => null)
    return answer?.uploads ?? []
}

async function signing() {
    requireSecure()
    const crypto = await e2ee()
    const data = await json(`${API}/olm/signing`)
    if (!data?.current) throw new UploadError("SIGNING_KEY_STALE")
    const pkcs8 = concat(PKCS8_ED25519, fromB64url(await crypto.decrypt(data.secret)))
    const exportable = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"])
    if ((await subtle.exportKey("jwk", exportable)).x !== data.signing) throw new UploadError("SIGNING_KEY_MISMATCH")
    const key = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"])
    return {
        account: data.account,
        async sign(context, payload) {
            const message = encoder.encode(`${context}\n${crypto.canonical(payload)}`)
            return b64url(new Uint8Array(await subtle.sign({ name: "Ed25519" }, key, message)))
        }
    }
}

async function verify(publicKey, context, payload, signature, canonical) {
    try {
        const key = await subtle.importKey("raw", fromB64url(publicKey), { name: "Ed25519" }, false, ["verify"])
        return await subtle.verify({ name: "Ed25519" }, key, fromB64url(signature),
            encoder.encode(`${context}\n${canonical(payload)}`))
    } catch {
        return false
    }
}

async function activeRooms() {
    const data = await json(`${API}/pool/rooms`)
    return new Set((data?.rooms ?? []).map(room => room.session_id))
}

async function storeOutbound(account, audience, session, meta) {
    const crypto = await e2ee()
    const key = globalThis.crypto.getRandomValues(new Uint8Array(32))
    const sealed = await crypto.encrypt(JSON.stringify({ ...meta, key: b64url(key), pickle: session.pickle(key) }))
    writeStore(`${OUTBOUND_STORE}${account}:${audience}`, sealed)
}

async function restoreOutbound(vz, account, audience, active) {
    const sealed = readStore(`${OUTBOUND_STORE}${account}:${audience}`)
    if (typeof sealed !== "string") return null
    try {
        const crypto = await e2ee()
        const saved = JSON.parse(await crypto.decrypt(sealed))
        if (!active.has(saved.session_id) || Date.now() - saved.created > ROOM_AGE) return null
        const session = vz.GroupSession.from_pickle(saved.pickle, fromB64url(saved.key))
        if (session.session_id !== saved.session_id || session.message_index >= ROOM_MESSAGES) {
            session.free()
            return null
        }
        return { session, created: saved.created }
    } catch {
        return null
    }
}

async function outbound(vz, signer, audience, renew = false) {
    const active = renew ? new Set() : await activeRooms()
    const restored = await restoreOutbound(vz, signer.account, audience, active)
    if (restored) return restored
    const session = new vz.GroupSession(vz.GroupSessionVersion.V1)
    try {
        const binding = { ctx: ROOM, account: signer.account, audience, session_id: session.session_id, ts: Date.now() }
        await json(`${API}/pool/rooms`, {
            method: "PUT",
            body: JSON.stringify({
                audience, session_id: session.session_id, session_key: session.session_key, binding,
                signature: await signer.sign(ROOM, binding)
            })
        })
        const created = Date.now()
        await storeOutbound(signer.account, audience, session, { session_id: session.session_id, created })
        return { session, created }
    } catch (error) {
        session.free()
        throw error
    }
}

async function send(vz, signer, subject, data, audience, renew) {
    const room = await outbound(vz, signer, audience, renew)
    try {
        const sessionId = room.session.session_id
        const ciphertext = room.session.encrypt(JSON.stringify({ t: POOL_MESSAGE, v: 1, subject, data }))
        await storeOutbound(signer.account, audience, room.session, { session_id: sessionId, created: room.created })
        const binding = { ctx: POOL, account: signer.account, subject, session_id: sessionId, ts: Date.now() }
        return await json(`${API}/pool`, {
            method: "PUT",
            body: JSON.stringify({ subject, session_id: sessionId, ciphertext, binding,
                                   signature: await signer.sign(POOL, binding) })
        })
    } finally {
        room.session.free()
    }
}

export async function publish(subject, data, audience = EVERYONE) {
    const [vz, signer] = await Promise.all([load(), signing()])
    let entry
    try {
        entry = await send(vz, signer, subject, data, audience, false)
    } catch (error) {
        if (error?.code !== "ROOM_RETIRED" && error?.code !== "UNKNOWN_ROOM") throw error
        writeStore(`${OUTBOUND_STORE}${signer.account}:${audience}`, null)
        entry = await send(vz, signer, subject, data, audience, true)
    }
    pools.delete(signer.account)
    return entry
}

export async function withdraw(subject) {
    const answer = await json(`${API}/pool`, { method: "DELETE", body: JSON.stringify({ subject }) })
    pools.clear()
    return !!answer?.withdrawn
}

function inboundSession(vz, sessionId, sessionKey) {
    const cached = inbound.get(sessionId)
    if (cached && cached.key === sessionKey) {
        inbound.delete(sessionId)
        inbound.set(sessionId, cached)
        return cached.session
    }
    cached?.session.free()
    const session = new vz.InboundGroupSession(sessionKey, vz.GroupSessionVersion.V1)
    if (session.session_id !== sessionId) {
        session.free()
        throw new UploadError("POOL_UNVERIFIED")
    }
    inbound.set(sessionId, { key: sessionKey, session })
    while (inbound.size > INBOUND_CACHE) {
        const [oldest, value] = inbound.entries().next().value
        value.session.free()
        inbound.delete(oldest)
    }
    return session
}

async function verifiedPool(account) {
    requireSecure()
    const data = await json(`${API}/pool/${encodeURIComponent(account)}`, { cache: "no-cache" })
    const { canonical } = await e2ee()
    const signing = data?.signing ?? {}
    const anchor = signing.binding ?? {}
    if (anchor.ctx !== SIGNING || anchor.account !== account || anchor.signing !== signing.signing
        || typeof signing.device_key !== "string" || anchor.device !== await fingerprint(signing.device_key)
        || !await verify(signing.device_key, SIGNING, anchor, signing.signature, canonical)) {
        throw new UploadError("POOL_UNVERIFIED")
    }

    const known = readStore(`${KNOWN_STORE}${account}`) ?? {}
    const keys = new Map()
    for (const room of data.rooms ?? []) {
        const binding = room.binding ?? {}
        if (typeof room.session_key !== "string") continue
        if (known[room.session_id] === room.session_key) {
            keys.set(room.session_id, room.session_key)
            continue
        }
        if (binding.ctx !== ROOM || binding.account !== account || binding.audience !== room.audience
            || binding.session_id !== room.session_id) continue
        if (!await verify(signing.signing, ROOM, binding, room.signature, canonical)) continue
        keys.set(room.session_id, room.session_key)
        known[room.session_id] = room.session_key
    }
    writeStore(`${KNOWN_STORE}${account}`, Object.fromEntries(Object.entries(known).slice(-KNOWN_ROOMS)))

    const entries = new Map()
    for (const entry of data.entries ?? []) {
        const binding = entry.binding ?? {}
        if (binding.ctx !== POOL || binding.account !== account || binding.subject !== entry.subject
            || binding.session_id !== entry.session_id) continue
        if (!await verify(signing.signing, POOL, binding, entry.signature, canonical)) continue
        const sessionKey = entry.session_key ?? keys.get(entry.session_id)
        if (!sessionKey) continue
        entries.set(entry.subject, { ...entry, session_key: sessionKey })
    }
    return { at: Date.now(), audiences: data.audiences ?? [EVERYONE], entries }
}

export function join(account, { fresh = false } = {}) {
    const cached = pools.get(account)
    if (!fresh && cached && Date.now() - cached.at < POOL_TTL) return Promise.resolve(cached)
    if (!joining.has(account)) {
        joining.set(account, verifiedPool(account).then(pool => {
            pools.set(account, pool)
            return pool
        }).finally(() => joining.delete(account)))
    }
    return joining.get(account)
}

export async function entry(account, subject) {
    const pool = await join(account)
    const found = pool.entries.get(subject)
    if (!found) return null
    const vz = await load()
    const session = inboundSession(vz, found.session_id, found.session_key)
    const result = session.decrypt(found.ciphertext)
    try {
        const plain = JSON.parse(result.plaintext)
        if (plain?.t !== POOL_MESSAGE || plain.v !== 1 || plain.subject !== subject) throw new UploadError("POOL_UNVERIFIED")
        return plain.data
    } finally {
        result.free()
    }
}

function uploadPath(src) {
    if (!src || src.startsWith("blob:") || src.startsWith("data:")) return null
    let url
    try { url = new URL(src, location.href) } catch { return null }
    if (url.origin !== location.origin || !url.pathname.startsWith(FILES)) return null
    return decodeURIComponent(url.pathname.slice(FILES.length))
}

function normalize(query) {
    if (typeof query !== "object" || query === null) return { id: String(query) }
    if (!query.url) return query
    const path = uploadPath(query.url)
    if (!path) throw new UploadError("UNKNOWN_UPLOAD_ID")
    return { path }
}

export function reference(item) {
    return new URL(item.url, location.origin).href
}

export function referenced(text) {
    return uploadPath(typeof text === "string" ? text.trim() : "") !== null
}

export async function describe(query) {
    const params = new URLSearchParams(normalize(query))
    return await json(`${API}/upload/url?${params}`)
}

async function descriptor(info) {
    if (info.key) {
        const crypto = await e2ee()
        if (crypto.ready()) return JSON.parse(await crypto.decrypt(info.key))
    }
    if (info.scheme !== "public" || !info.account) throw new UploadError("UPLOAD_LOCKED")
    let key = await entry(info.account, info.subject)
    if (!key) {
        await join(info.account, { fresh: true })
        key = await entry(info.account, info.subject)
    }
    if (!key) throw new UploadError("UPLOAD_LOCKED")
    return key
}

async function download(url) {
    const response = await fetch(url, { credentials: "same-origin", cache: "no-cache" })
    if (!response.ok) throw new UploadError(`HTTP_${response.status}`)
    return response
}

export async function file(query) {
    const info = await describe(query)
    const response = await download(info.url)
    if (!info.scheme || info.scheme === PLAIN) {
        const blob = await response.blob()
        return { blob, name: info.name ?? null, mime: info.mimetype || blob.type || "application/octet-stream" }
    }
    const key = await descriptor(info)
    const blob = await decryptFile(await response.arrayBuffer(), key)
    return { blob, name: key.name ?? info.name ?? null, mime: key.mime || info.mimetype || "application/octet-stream" }
}

export async function blob(query) {
    return (await file(query)).blob
}

export function open(query) {
    const cacheKey = typeof query === "object" ? JSON.stringify(query) : String(query)
    if (!opened.has(cacheKey)) {
        opened.set(cacheKey, blob(query).then(value => URL.createObjectURL(value)).catch(error => {
            opened.delete(cacheKey)
            throw error
        }))
    }
    return opened.get(cacheKey)
}

export async function resolve(src) {
    const path = uploadPath(src)
    if (!path) return src
    const info = await describe({ path })
    if (!info.scheme || info.scheme === PLAIN) return src
    return await open({ path })
}

function sealedForm(cipher, name, key, mime) {
    const form = new FormData()
    form.append("file", cipher, name || "upload")
    form.append("key", key)
    form.append("type", mime)
    return form
}

async function rotate(item, crypto) {
    const key = JSON.parse(await crypto.decrypt(item.key))
    const response = await download(item.url)
    const plain = await decryptFile(await response.arrayBuffer(), key)
    const fresh = await encryptFile(plain, { name: key.name, mime: key.mime })
    await transfer("PUT", `${API}/upload/${item.id}/content`,
        sealedForm(fresh.cipher, item.name, await crypto.encrypt(JSON.stringify(fresh.key)), fresh.key.mime))
}

async function encryptStored(item, crypto, onProgress) {
    const response = await download(item.url)
    const mime = item.mimetype || "application/octet-stream"
    const fresh = await encryptFile(await response.blob(), { name: item.name, mime })
    await transfer("PUT", `${API}/upload/${item.id}/content`,
        sealedForm(fresh.cipher, item.name, await crypto.encrypt(JSON.stringify(fresh.key)), mime), { onProgress })
}

async function decryptStored(item, crypto, onProgress) {
    const key = JSON.parse(await crypto.decrypt(item.key))
    const response = await download(item.url)
    const plain = await decryptFile(await response.arrayBuffer(), key)
    const form = new FormData()
    form.append("file", plain, key.name || item.name || "upload")
    form.append("type", key.mime || item.mimetype || "application/octet-stream")
    await transfer("PUT", `${API}/upload/${item.id}/content`, form, { onProgress })
}

async function fulfilPass(crypto) {
    const data = await json(`${API}/uploads`)
    let published = 0
    let rotated = 0
    for (const item of data?.uploads ?? []) {
        if (!item.key || !item.pending) continue
        if (item.pending === "rotate") {
            await rotate(item, crypto)
            rotated += 1
        } else if (item.pending === "publish" && item.published) {
            await publish(item.subject, JSON.parse(await crypto.decrypt(item.key)), item.audience)
            published += 1
        }
    }
    return { published, rotated }
}

export function fulfil() {
    fulfilling ??= (async () => {
        const crypto = await e2ee()
        const total = { published: 0, rotated: 0 }
        if (!crypto.ready()) return total
        for (let pass = 0; pass < 3; pass++) {
            const done = await fulfilPass(crypto)
            total.published += done.published
            total.rotated += done.rotated
            if (!done.rotated) break
        }
        if (total.published || total.rotated) opened.clear()
        return total
    })().finally(() => fulfilling = null)
    return fulfilling
}

export function recrypt({ onProgress } = {}) {
    recrypting ??= (async () => {
        const crypto = await e2ee()
        if (!crypto.ready()) throw new UploadError("BROWSER_LOCKED")
        const data = await json(`${API}/uploads`)
        const due = (data?.uploads ?? []).filter(item => item.pending === ENCRYPT || item.pending === DECRYPT)
        const failed = []
        onProgress?.(due.length ? 0 : 1)
        for (const [index, item] of due.entries()) {
            const step = share => onProgress?.((index + Math.min(1, share)) / due.length)
            try {
                if (item.pending === ENCRYPT) await encryptStored(item, crypto, step)
                else await decryptStored(item, crypto, step)
            } catch (error) {
                failed.push({ id: item.id, code: error?.code ?? "UNKNOWN_ERROR" })
            }
            step(1)
        }
        opened.clear()
        await fulfil().catch(() => null)
        return { converted: due.length - failed.length, failed }
    })().finally(() => recrypting = null)
    return recrypting
}

export async function setEncrypted(value, { onProgress } = {}) {
    const answer = await json(`${API}/upload/settings`, { method: "PATCH", body: JSON.stringify({ encrypted: !!value }) })
    await available({ fresh: true })
    return { ...answer, ...await recrypt({ onProgress }) }
}

export async function setAudience(id, audience) {
    const entry = await json(`${API}/upload/${encodeURIComponent(id)}/audience`, {
        method: "PATCH", body: JSON.stringify({ audience })
    })
    if (entry?.pending) await fulfil().catch(() => null)
    opened.clear()
    return entry
}

export async function share(id) {
    const entry = await json(`${API}/upload/${encodeURIComponent(id)}/share`, { method: "POST" })
    if (entry?.pending) await fulfil().catch(() => null)
    return entry
}

export async function unshare(id) {
    const entry = await json(`${API}/upload/${encodeURIComponent(id)}/share`, { method: "DELETE" })
    if (entry?.pending) await fulfil().catch(() => null)
    opened.clear()
    return entry
}

function reveal(image) {
    const declared = image.getAttribute("data-users-upload")
    const path = uploadPath(declared ?? image.getAttribute("src"))
    if (!path || image.dataset.usersRevealed === path) return
    image.dataset.usersRevealed = path
    resolve(declared ?? image.getAttribute("src")).then(url => {
        if (image.dataset.usersRevealed === path && image.getAttribute("src") !== url) image.src = url
    }).catch(() => image.dispatchEvent(new Event("users:upload-error")))
}

function scan(root) {
    if (root instanceof HTMLImageElement) return reveal(root)
    root.querySelectorAll?.(`img[src*="${FILES}"], img[data-users-upload]`).forEach(reveal)
}

function watch() {
    scan(document)
    new MutationObserver(records => {
        for (const record of records) {
            if (record.type === "attributes") scan(record.target)
            else record.addedNodes.forEach(node => node.nodeType === 1 && scan(node))
        }
    }).observe(document.documentElement, {
        subtree: true, childList: true, attributes: true, attributeFilter: ["src", "data-users-upload"]
    })
}

window.wf.adt.users = {
    ...window.wf.adt.users,
    uploads: {
        secure, load, available, list, encryptFile, decryptFile, transfer, upload, publish, withdraw, join, entry,
        reference, referenced, describe, file, blob, open, resolve, fulfil, recrypt, setEncrypted, setAudience, share,
        unshare
    }
}
window.dispatchEvent(new Event("users:uploads"))

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", watch)
else watch()
