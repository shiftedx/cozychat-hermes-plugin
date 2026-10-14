import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

// The Hermes disk loader supplies these three imports. Supply tiny element/hook doubles to
// exercise the actual controller and renderer in Node, without installing React or a bundler.
const source = readFileSync(new URL('../desktop/plugin.js', import.meta.url), 'utf8')
const sandbox = {
  Button: 'button', ROUTES_AREA: 'routes', SIDEBAR_NAV_AREA: 'sidebar.nav',
  jsx: (type, props, key) => ({ type, props, key }), jsxs: (type, props, key) => ({ type, props, key }),
  useEffect() {}, useState: value => [value, () => {}],
  setInterval, clearInterval, Date,
}
vm.createContext(sandbox)
vm.runInContext(source.replace(/^import .*$/gm, '').replace('export default', 'globalThis.plugin =') +
  '\nglobalThis.api = { createController, PairingView, ENABLE_COPY }', sandbox)
const { createController, PairingView, ENABLE_COPY } = sandbox.api

function state(overrides = {}) {
  return { first_visit: false, window: null, pending: null, phones: [],
    reachable: { enabled: true, installed: false, note: null }, ...overrides }
}
const windowState = () => state({ window: { id: 'window-a', remaining: 600, exp: 1600 } })
const qr = { window_id: 'window-a', png: 'data:image/png;base64,TEST', link: 'cozychat://pair-relay?d=SECRET' }
const model = value => ({ state: value, qr: null, busy: false, error: null, disabled: false })

function nodes(element) {
  if (element == null || typeof element !== 'object') return []
  if (Array.isArray(element)) return element.flatMap(nodes)
  return [element, ...nodes(element.props?.children)]
}
function text(element) {
  if (element == null) return ''
  if (typeof element === 'string' || typeof element === 'number') return String(element)
  if (Array.isArray(element)) return element.map(text).join(' ')
  if (element.type === 'style') return ''
  return text(element.props?.children)
}

test('computer page offers removal with rotation and standalone key rotation', () => {
  const calls = []
  const rendered = PairingView({ model: model(state({ phones: [{ id: 'phone-a', name: 'Phone A' }],
    rotation: { available: true, pending: false } })), act: (...args) => calls.push(args) })
  const buttons = nodes(rendered).filter(node => node.type === 'button')
  buttons.find(node => text(node) === 'Remove and rotate key').props.onClick()
  buttons.find(node => text(node) === 'Rotate API key').props.onClick()
  assert.equal(calls[0][0], '/phones/phone-a')
  assert.equal(calls[0][1].rotate, true)
  assert.equal(calls[0][2], 'DELETE')
  assert.equal(calls[1][0], '/rotate')
  const pending = PairingView({ model: model(state({ rotation: { available: true, pending: true } })), act() {} })
  assert.match(text(pending), /Waiting for Hermes/)
  assert.equal(nodes(pending).filter(node => node.type === 'button' && text(node) === 'Rotate API key').length, 0)
})

test('registers the CozyChat workspace route and sidebar row with only admitted imports', () => {
  let contributions
  sandbox.plugin.register({ registerMany: value => { contributions = value } })
  assert.equal(sandbox.plugin.id, 'cozychat')
  assert.equal(contributions[0].area, 'routes')
  assert.equal(contributions[0].data.path, '/cozychat')
  assert.equal(contributions[1].data.label, 'CozyChat')
  assert.equal(contributions[1].data.path, '/cozychat')
  assert.deepEqual([...source.matchAll(/^import .* from '([^']+)'$/gm)].map(match => match[1]),
    ['@hermes/plugin-sdk', 'react', 'react/jsx-runtime'])
})

test('first visit automatically opens a QR with no extra click', async () => {
  const calls = []
  let current
  const controller = createController({ rest: async (path, options) => {
    calls.push([path, options])
    if (path === '/pair/state') return state({ first_visit: true })
    if (path === '/pair/open') return windowState()
    return qr
  } }, value => { current = value })
  await controller.load(true)
  assert.deepEqual(calls.map(call => call[0]), ['/pair/state', '/pair/open', '/pair/qr'])
  assert.equal(calls[1][1].body.automatic, true)
  assert.equal(current.qr.png, qr.png)
  const rendered = PairingView({ model: current, act() {} })
  assert.equal(nodes(rendered).filter(node => node.type === 'img').length, 1)
  assert.match(text(rendered), /Code closes in 10:00/)
  assert.match(text(rendered), /straight to this computer over your Wi-Fi/)
})

test('backend disabled renders one enable line without throwing or controls', async () => {
  let current
  const controller = createController({ rest: async () => { throw Object.assign(new Error('off'), { status: 503 }) } }, value => { current = value })
  await controller.load(true)
  const rendered = PairingView({ model: current, act() {} })
  assert.equal(current.error, ENABLE_COPY)
  assert.equal(text(rendered).split(ENABLE_COPY).length, 2)
  assert.equal(nodes(rendered).filter(node => ['button', 'input', 'img'].includes(node.type)).length, 0)
})

test('an automatic setup error remains actionable and does not claim the plugin is off', async () => {
  let current
  const controller = createController({ rest: async path => {
    if (path === '/pair/state') return state({ first_visit: true })
    throw Object.assign(new Error('Restart Hermes after your chat finishes.'), { status: 409 })
  } }, value => { current = value })
  await controller.load(true)
  const rendered = PairingView({ model: current, act() {} })
  assert.equal(current.disabled, false)
  assert.match(text(rendered), /Restart Hermes/)
  assert.match(text(rendered), /Pair a phone/)
})

test('Hermes HTTP errors show authored copy and keep setup guidance through polling', async () => {
  let current
  const controller = createController({ rest: async path => {
    if (path === '/pair/state') return state({ first_visit: true })
    throw Object.assign(new Error('409: {"detail":"Restart Hermes after your chat finishes."}'), { statusCode: 409 })
  } }, value => { current = value })
  await controller.load(true)
  await controller.load()
  assert.equal(current.error, 'Restart Hermes after your chat finishes.')
  assert.equal(current.disabled, false)
})

test('countdown withdraws both the QR and secret link at expiry even if the next poll fails', async () => {
  let current, now = 0
  const controller = createController({ rest: async path => path === '/pair/state'
    ? state({ window: { id: 'window-a', remaining: 2 } }) : qr }, value => { current = value }, () => now)
  await controller.load()
  now = 2000
  controller.tick()
  const rendered = PairingView({ model: current, act() {} })
  assert.equal(current.qr, null)
  assert.equal(nodes(rendered).filter(node => ['img', 'textarea'].includes(node.type)).length, 0)
  assert.match(text(rendered), /Pair a phone/)
})

test('confirmation shows exact leading-zero code and wires Approve and Refuse to the attempt', () => {
  const calls = []
  const rendered = PairingView({ model: model(state({ window: { remaining: 60 },
    pending: { id: 'attempt-2', phone_name: 'Kyle’s iPhone', code: '001002' } })), act: (...args) => calls.push(args) })
  assert.match(text(rendered), /001 002/)
  const buttons = nodes(rendered).filter(node => node.type === 'button')
  buttons.forEach(button => button.props.onClick())
  assert.equal(calls[0][0], '/pair/approve')
  assert.equal(calls[0][1].id, 'attempt-2')
  assert.equal(calls[1][0], '/pair/refuse')
  assert.equal(nodes(rendered).filter(node => node.type === 'img').length, 0)
})

test('paired phones have named Remove controls and the reachable switch sends a boolean', () => {
  const calls = []
  const rendered = PairingView({ model: model(state({ phones: [{ id: 'phone-key', name: 'Phone A' }] })), act: (...args) => calls.push(args) })
  const remove = nodes(rendered).find(node => node.props?.['aria-label'] === 'Remove Phone A')
  remove.props.onClick()
  assert.equal(calls[0][0], '/phones/phone-key')
  assert.equal(calls[0][2], 'DELETE')
  const toggle = nodes(rendered).find(node => node.props?.role === 'switch')
  assert.equal(toggle.props.checked, true)
  toggle.props.onChange({ target: { checked: false } })
  assert.equal(calls[1][0], '/reachable')
  assert.equal(calls[1][1].enabled, false)
})

test('after approval a closed window clears the cached QR', async () => {
  let current, opened = true
  const controller = createController({ rest: async path => {
    if (path === '/pair/state') return opened ? windowState() : state({ phones: [{ id: 'key', name: 'Phone' }] })
    if (path === '/pair/qr') return qr
    opened = false
    return { ok: true }
  } }, value => { current = value })
  await controller.load()
  await controller.act('/pair/approve', { id: 'attempt' })
  assert.equal(current.qr, null)
  assert.equal(current.state.phones.length, 1)
})

test('a replaced pairing window clears its old QR before the next PNG arrives', async () => {
  let current, changedWindow = false, release
  const controller = createController({ rest: async path => {
    if (path === '/pair/state') return changedWindow ? state({ window: { id: 'window-b', remaining: 600 } }) : windowState()
    if (!changedWindow) return qr
    return new Promise(done => { release = done })
  } }, value => { current = value })
  await controller.load()
  changedWindow = true
  const pending = controller.load()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(current.qr, null)
  release({ ...qr, window_id: 'window-b' })
  await pending
  assert.equal(current.qr.window_id, 'window-b')
})

test('a phone already removed elsewhere shows its message without disabling the plugin', async () => {
  let current
  const controller = createController({ rest: async path => {
    if (path === '/pair/state') return state()
    throw Object.assign(new Error('404: {"detail":"This phone has already been removed."}'), { statusCode: 404 })
  } }, value => { current = value })
  await controller.load()
  await controller.act('/phones/old', {}, 'DELETE')
  assert.equal(current.disabled, false)
  assert.equal(current.error, 'This phone has already been removed.')
})

test('busy actions cannot send duplicate approvals', async () => {
  let release, actions = 0
  const controller = createController({ rest: async path => {
    if (path === '/pair/state') return state()
    actions++
    await new Promise(resolve => { release = resolve })
  } }, () => {})
  const pending = controller.act('/pair/approve', { id: 'attempt' })
  await controller.act('/pair/approve', { id: 'attempt' })
  release()
  await pending
  assert.equal(actions, 1)
})

test('a disposed page neither publishes nor automatically opens a late first-visit response', async () => {
  let resolve, calls = 0, published = 0
  const controller = createController({ rest: () => { calls++; return new Promise(done => { resolve = done }) } }, () => { published++ })
  const pending = controller.load(true)
  controller.dispose()
  resolve(state({ first_visit: true }))
  await pending
  assert.equal(calls, 1)
  assert.equal(published, 0)
})


test('existing Hermes service locks Keep reachable on with its explanation', () => {
  const rendered = PairingView({ model: model(state({ reachable: {
    enabled: true, installed: true, owned: false, editable: false,
    note: 'Already kept running by your Hermes service',
  } })), act() {} })
  const toggle = nodes(rendered).find(node => node.props?.role === 'switch')
  assert.equal(toggle.props.checked, true)
  assert.equal(toggle.props.disabled, true)
  assert.match(text(rendered), /Already kept running by your Hermes service/)
})

test('turning Keep reachable off says plainly that a running Hermes keeps running', () => {
  const rendered = PairingView({ model: model(state({ reachable: { enabled: false, installed: false, owned: false, editable: true, note: null } })), act() {} })
  assert.match(text(rendered), /Hermes keeps running until you quit it; it won't start by itself next time\./)
})

test('pending notification cleanup remains retryable after a page reload', async () => {
  let pending = true, current
  const calls = []
  const controller = createController({ rest: async (path, options) => {
    calls.push([path, options?.method])
    if (path === '/pair/state') return state({ push_cleanup_pending: pending })
    assert.equal(path, '/push/cleanup')
    pending = false
    return { ok: true, pending_cleanup: false }
  } }, value => { current = value })
  await controller.load()
  assert.equal(current.cleanupPending, true)
  assert.match(current.error, /cleanup could not finish/)
  assert.match(text(PairingView({ model: current, act() {} })), /Try again/)
  await controller.act('/push/cleanup')
  assert.equal(current.cleanupPending, false)
  assert.equal(current.error, null)
  assert.ok(calls.some(([path, method]) => path === '/push/cleanup' && method === 'POST'))
})

test('Hermes without its secret scope shows the update copy and publishes no QR', async () => {
  let current
  const calls = []
  const controller = createController({ rest: async path => {
    calls.push(path)
    if (path === '/pair/state') return state({ update_required: 'Update Hermes to use CozyChat' })
    throw new Error('no other request may be made: ' + path)
  } }, value => { current = value })
  await controller.load(true)
  assert.equal(current.error, 'Update Hermes to use CozyChat')
  assert.equal(current.qr, null)
  assert.equal(current.disabled, true)
  assert.deepEqual(calls, ['/pair/state'])
})

test('each paired phone row groups its two removal buttons in one right-aligned actions container', () => {
  const rendered = PairingView({ model: model(state({ phones: [{ id: 'phone-a', name: 'Phone A' }],
    rotation: { available: true, pending: false } })), act() {} })
  const row = nodes(rendered).find(node => node.props?.className === 'cozychat-phone')
  assert.equal(row.props.children.length, 2)
  const actions = row.props.children[1]
  assert.equal(actions.props.className, 'cozychat-phone-actions')
  const buttons = actions.props.children.filter(Boolean)
  assert.equal(buttons.map(text).join('|'), 'Remove|Remove and rotate key')
  assert.equal(buttons[0].props.variant, 'destructive')
  assert.match(source, /\.cozychat-phone-actions\{[^}]*justify-content:flex-end[^}]*flex-wrap:wrap|\.cozychat-phone-actions\{[^}]*flex-wrap:wrap[^}]*justify-content:flex-end/)
})
