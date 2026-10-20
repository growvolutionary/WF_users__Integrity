# Static e2ee.js and session.js integrity

This repository contains the version history of the two static JavaScript files the `users` Additive
serves for its end-to-end encryption — `e2ee.js`, which holds all cryptography, and `session.js`, which
unlocks the account key for a session — with their original source and correlating hashes.

## Contents

| Path              | Meaning                                                                                                                |
|-------------------|------------------------------------------------------------------------------------------------------------------------|
| `e2ee/v<N>.js`    | The published source of every version of `static/js/e2ee.js` (artifact `users_e2ee`).                                  |
| `session/v<N>.js` | The published source of every version of `static/js/session.js` (artifact `users_session`).                            |
| `generate.py`     | Computes the SHA-256 of every version and writes `manifest.json` (and `<artifact>/hashes/`).                           |
| `manifest.json`   | The public reference, format 2: per artifact one entry per version (`version`, `file`, `sha256`, `size`) and `latest`. |
| `.gitattributes`  | Pins `e2ee/*.js` and `session/*.js` to LF, so a checkout on any platform hashes to the same value.                     |

`generate.py` hashes the content as stored in git: CRLF line endings count as LF, so a clone made
before `.gitattributes` existed still reproduces the published value. The output is deterministic and
carries no timestamps; running it twice produces identical files. The `hashes/` folders are a local
by-product and not committed, `manifest.json` is.

```bash
python generate.py
```

The `users` Additive clones this repository, runs `generate.py` exactly once per integrity run as a
subprocess of its own interpreter, recomputes every hash itself and only reports versions whose hashes
it could reproduce. A failing or non-reproducible run is reported as "reference unavailable", never as
a fresh result. Peers fetch `manifest.json` from this repository directly (not through the host) and
compare it with the script the host actually serves.

## What the hashes prove

A matching hash proves that a host serves the bytes published here — nothing more. Every QR code a
browser shows for a handshake or a link carries the hashes and versions of both scripts; the mobile SDK
accepts them when the host's peers confirm them, or — without peers — when its release pins them (a map
from version to hash per script). It does not prove that the published code is free of bugs, and it
cannot prove what a host does on its server side.
A host that serves an older version than `latest` is reported as *outdated*, one that serves bytes
that match no version as a *reference mismatch*.

## Manual Trust Check

The account area of an application runs its own trust check before it shows anything confidential.
That check runs inside the page the host delivered — a compromised host could manipulate it. The
snippet below repeats the check from a page the host does not control: it loads both scripts from the
host itself, hashes them in your browser and compares the result with the published `manifest.json` of
this repository, with the hashes the host claims and with the hashes the host's peers observed.

**Get the snippet from here, not from the application.** Read it on GitHub
(`https://github.com/growvolutionary/WF_users__Integrity`), compare it with the version in the
repository history, and only run code you have read. It is short on purpose.

1. Open a new, empty tab (`about:blank`). Do not run it on the application's own page: that page's
   scripts could have replaced `fetch` or `crypto`.
2. Open the developer tools with `CTRL + SHIFT + I` (`CMD + OPTION + I` on macOS) and switch to
   **Console**.
3. Edit `HOST` (and, if you know peers from an independent source, `EXTRA_PEERS`), paste the block and
   press Enter. Some browsers ask you to type `allow pasting` first.

```js
(async () => {
    const HOST = "https://example.org"
    const EXTRA_PEERS = []
    const USERS = "/users"
    const SCRIPTS = { users_e2ee: "/static/js/e2ee.js", users_session: "/static/js/session.js" }
    const MANIFEST = "https://raw.githubusercontent.com/growvolutionary/WF_users__Integrity/main/manifest.json"

    const ORIGIN = new URL(HOST).origin
    const ARTIFACTS = Object.keys(SCRIPTS)
    const HOST_API = "/peering/api/v1"
    const PEER_API = "/api/v1"
    const load = url => fetch(url, { credentials: "omit", cache: "no-store", redirect: "error" })
        .then(response => response.ok ? response : Promise.reject(new Error(`HTTP ${response.status}`)))
    const json = url => load(url).then(response => response.json())
    const api = (origin, base, path) => json(`${origin}${base}${path}`)
    const hex = buffer => Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, "0")).join("")
    const sha256 = url => load(url).then(response => response.arrayBuffer())
        .then(bytes => crypto.subtle.digest("SHA-256", bytes)).then(digest => ({ hash: hex(digest) }))
    const b64 = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")
        + "=".repeat((4 - text.length % 4) % 4)), char => char.charCodeAt(0))
    const canonical = value => value === null ? "null"
        : Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
        : typeof value === "object" ? `{${Object.keys(value).sort()
            .map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
        : JSON.stringify(value)
    const verify = async (key, context, payload, signature) => {
        const publicKey = await crypto.subtle.importKey("raw", b64(key), { name: "Ed25519" }, false, ["verify"])
        const message = new TextEncoder().encode(`${context}\n${canonical(payload)}`)
        return crypto.subtle.verify({ name: "Ed25519" }, publicKey, b64(signature), message)
    }
    const safe = promise => promise.then(value => value, error => ({ error: error.message }))

    const [manifest, claim, listed, ...served] = await Promise.all([
        safe(json(MANIFEST)), safe(json(`${ORIGIN}${USERS}/api/v1/integrity`)), safe(api(ORIGIN, HOST_API, "/peers")),
        ...ARTIFACTS.map(artifact => safe(sha256(`${ORIGIN}${USERS}${SCRIPTS[artifact]}`)))
    ])
    const live = Object.fromEntries(ARTIFACTS.map((artifact, index) => [artifact, served[index]]))
    const claimed = Object.fromEntries(ARTIFACTS.map(artifact =>
        [artifact, (claim.artifacts || []).find(item => item.id === artifact) || {}]))
    const published = (artifact, hash) => {
        const entry = (manifest.artifacts || {})[artifact] || {}
        return { version: (entry.versions || []).find(item => item.sha256 === hash)?.version ?? null,
                 latest: entry.latest ?? null }
    }

    const peers = [...new Set([...(listed.peers || []).map(peer => peer.url), ...EXTRA_PEERS])]
        .filter(url => /^https:\/\//.test(url || ""))
    const rows = await Promise.all(peers.map(async url => {
        const [node, trust, checkpoint, ...hashes] = await Promise.all([
            safe(api(url, PEER_API, "/node")), safe(api(url, PEER_API, "/trust")),
            safe(api(url, PEER_API, "/checkpoints/latest")),
            ...ARTIFACTS.map(artifact => safe(api(url, PEER_API, `/hash?id=${artifact}`)))
        ])
        const statement = node.statement || {}
        const identity = !node.error && statement.url === url
            && await verify(statement.key, "wf-peering-node-v1", statement, node.signature || "").catch(() => false)
        const signed = identity && !trust.error && trust.key === statement.key
            && await verify(trust.key, "wf-trust-v1", { node: trust.node, key: trust.key, report: trust.report }, trust.signature)
                .catch(() => false)
        const assessment = signed && trust.report.host?.target === ORIGIN ? trust.report.host : {}
        return {
            peer: url,
            reachable: !node.error,
            signed_identity: identity,
            peers_this_host: statement.host === ORIGIN,
            score: assessment.score ?? null,
            level: assessment.level ?? null,
            basis: assessment.basis ?? null,
            observed: Object.fromEntries(ARTIFACTS.map((artifact, index) => [artifact, hashes[index].observation?.observed ?? null])),
            status: Object.fromEntries(ARTIFACTS.map((artifact, index) => [artifact, hashes[index].observation?.status ?? null])),
            checkpoint: checkpoint.error ? null : `${checkpoint.day} ${checkpoint.status}`,
            ledger_size: checkpoint.content?.ledger?.size ?? null,
            ledger_root: checkpoint.content?.ledger?.root ?? null
        }
    }))
    const confirmed = rows.filter(row => row.signed_identity && row.peers_this_host)

    console.table(Object.fromEntries(ARTIFACTS.map(artifact => {
        const { version, latest } = published(artifact, live[artifact].hash)
        const observations = confirmed.filter(row => row.observed[artifact])
        return [artifact, {
            served_to_you: live[artifact].hash ?? live[artifact].error,
            published_version: version, latest_version: latest,
            host_claims: claimed[artifact].hash ?? null,
            peers_agree: `${observations.filter(row => row.observed[artifact] === live[artifact].hash).length}/${observations.length}`
        }]
    })))
    if (rows.length) console.table(rows)

    const findings = []
    if (manifest.error) findings.push(`The published manifest could not be loaded (${manifest.error}): the scripts are UNCLEAR.`)
    if (claim.error) findings.push(`The host does not answer its integrity claim (${claim.error}).`)
    for (const artifact of ARTIFACTS) {
        const hash = live[artifact].hash
        if (!hash) {
            findings.push(`${artifact} could not be loaded from the host (${live[artifact].error}). Hosts before the `
                + "cross-origin release of the users Additive block this read: compare `sha256sum` of the file with "
                + "manifest.json instead.")
            continue
        }
        const { version, latest } = published(artifact, hash)
        if (!manifest.error && !version) findings.push(`${artifact}: the bytes you received match no published version.`)
        if (version && latest && version !== latest) findings.push(`${artifact}: the host serves ${version}, the latest is ${latest}.`)
        if (claimed[artifact].hash && claimed[artifact].hash !== hash) {
            findings.push(`${artifact}: the host claims ${claimed[artifact].hash}, but served you ${hash}.`)
        }
        if (claimed[artifact].url && claimed[artifact].url !== `${USERS}${SCRIPTS[artifact]}`) {
            findings.push(`${artifact}: the host claims the script at ${claimed[artifact].url}; this check read ${USERS}${SCRIPTS[artifact]}.`)
        }
        for (const row of confirmed) {
            if (row.observed[artifact] && row.observed[artifact] !== hash) {
                findings.push(`${row.peer} observed a different ${artifact} than the host served you.`)
            }
            if (["served-mismatch", "reference-mismatch", "outdated"].includes(row.status[artifact])) {
                findings.push(`${row.peer} reports for ${artifact}: ${row.status[artifact]}.`)
            }
        }
    }
    for (const row of confirmed) {
        if (row.level === "critical" || row.level === "warning") findings.push(`${row.peer} rates the host: ${row.level}.`)
    }
    const roots = {}
    for (const row of confirmed.filter(row => row.ledger_root)) (roots[row.ledger_size] ??= new Set()).add(row.ledger_root)
    for (const [size, set] of Object.entries(roots)) {
        if (set.size > 1) findings.push(`Peers disagree about the ledger of size ${size}: possible split view.`)
    }
    if (listed.error && !EXTRA_PEERS.length) {
        console.log("The host lists no peers: only your own hashes and the published manifest were compared.")
    } else if (!confirmed.length) {
        findings.push("No peer of this host could be verified: the peer side of the result is UNCLEAR, not good.")
    }

    console.log(findings.length ? findings.join("\n") : "No deviation found: the scripts you received are published "
        + "versions and agree with the host's claim and with every verified peer.")
    console.log("Limits: the host can tell this request from your application tab and could serve it different bytes; "
        + "the host chose which peers to list; peers may share an operator; a browser cannot inspect TLS "
        + "certificates or DNS; matching values prove agreement, not correctness.")
})()
```

What the snippet does — and what it does not:

- It only sends `GET` requests without credentials: for both scripts and the host's integrity claim
  (`/users/api/v1/integrity`) to the host, for `manifest.json` to GitHub, to the host's public peering
  API under `/peering/api/v1` and to every peer's under `/api/v1` (the peering app). It reads no
  cookies, passwords, local keys, session data or storage, uses no `eval` and loads no further code —
  the scripts are hashed as bytes, never executed.
- It hashes `e2ee.js` and `session.js` exactly as the host served them to your browser and looks the
  hashes up in `manifest.json`, read straight from this repository: a hash that matches no version is
  a *reference mismatch*, an older version than `latest` is *outdated*.
- It compares your hashes with the hashes the host claims and with the hashes each peer observed, checks
  the Ed25519 signatures of every peer's identity and trust report, and compares the peers' latest
  checkpoint roots. Without peering, the comparison with the manifest still stands on its own.
- The host answers these reads with `Access-Control-Allow-Origin: *` for exactly the two scripts and
  its integrity claim. Older versions of the `users` Additive do not; the snippet then says so, and the
  fallback is to download both files and compare `sha256sum e2ee.js session.js` with `manifest.json`.
- The browser verifies TLS for every `https` request, but a script cannot inspect certificates, DNS
  records or the operator behind a peer. Peers check those themselves; their results appear as their
  signed claims.
- The host can distinguish this request (no cookie, empty origin) from the one your application tab
  makes and could answer it with other bytes. Peers face the same limit. The check inside the account
  area hashes the copy the page actually loaded; the two complement each other.
- The list of peers comes from the host. A compromised host can leave peers out. Add peers you know
  from an independent source to `EXTRA_PEERS`.
- Peers that do not answer or block cross-origin requests are listed as unreachable. Missing answers
  make the result unclear — they are neither a confirmation nor proof of manipulation.

A clean result means that the bytes you received are published versions and that the host's claims and
the peers you reached agree with them. It is not a guarantee that the host is uncompromised.

## License

The code of this repository is a public integrity promise that belongs to
the WebFluid "users" Additive. The code is licensed as [ARR (All rights reserved)](LICENSE).
