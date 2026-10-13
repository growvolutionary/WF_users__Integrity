/********************************************************************
 *                                                                  *
 *    Copyright © 2026 GrowVolution Media, Inh. Pierre Schkoldow    *
 *                                                                  *
 *       This script unlocks the account key of the WebFluid        *
 *     "users" Additive for the current session, so every page      *
 *         can use its end-to-end encryption. To keep your          *
 *     application transparent and secure, you should not edit      *
 *    or change its content by yourself. Additionally we highly     *
 *         recommend to add the "peering" Additive to your          *
 *       application and to not remove the "users" Additive's       *
 *                        peering features.                         *
 *                                                                  *
 ********************************************************************/

const SOURCE = import.meta.url
const PREFIX = new URL(SOURCE).pathname.replace(/\/static\/js\/session\.js$/, "")
const TIMEOUT = 10000

let scriptHash = null


function crypto() {
    const loaded = window.wf?.adt?.users?.e2ee
    if (loaded) return Promise.resolve(loaded)

    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("e2ee.js is not loaded.")), TIMEOUT)
        window.addEventListener("users:e2ee", () => {
            clearTimeout(timer)
            resolve(window.wf.adt.users.e2ee)
        }, { once: true })
    })
}

function hex(buffer) {
    return Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("")
}


export function hash() {
    scriptHash ??= fetch(SOURCE, { cache: "force-cache", credentials: "same-origin" })
        .then(response => {
            if (!response.ok) throw new Error(`Loading ${SOURCE} answered HTTP ${response.status}.`)
            return response.arrayBuffer()
        })
        .then(source => globalThis.crypto.subtle.digest("SHA-256", source))
        .then(hex)
        .catch(error => {
            scriptHash = null
            throw error
        })
    return scriptHash
}

export async function state() {
    const response = await fetch(`${PREFIX}/api/v1/mobile/session`, { credentials: "same-origin" })
        .catch(() => null)
    if (!response) return null
    if (response.status === 401) await crypto().then(e2ee => e2ee.reset()).catch(() => null)
    return response.ok ? await response.json().catch(() => null) : null
}

export async function unlockVault(user) {
    const e2ee = await crypto()
    if (e2ee.ready()) return true
    const key = await e2ee.vaultKey(user)
    if (!key) return false

    const response = await fetch(`${PREFIX}/api/v1/browser/keys/${encodeURIComponent(key)}`, { credentials: "same-origin" })
        .catch(() => null)
    if (!response?.ok) return false
    const data = await response.json().catch(() => null)
    return data?.wrapped ? e2ee.unlockVault({ user, wrapped: data.wrapped }) : false
}

export async function unlock() {
    const [e2ee, session] = await Promise.all([crypto(), state()])
    if (!session?.share || !session.binding) {
        if (session && !session.device && await unlockVault(session.user_id)) return session
        await e2ee.reset()
        return session
    }

    await e2ee.unlock({ share: session.share, binding: session.binding, user: session.user_id })
    return session
}


window.wf.adt.users = {
    ...window.wf.adt.users,
    session: { hash, state, unlock, unlockVault }
}
window.dispatchEvent(new Event("users:session"))
