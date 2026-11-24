const me = Math.random().toString(36).slice(2)
const lang = (navigator.language || 'en').toLowerCase()
const fr = lang.startsWith('fr')

const T = fr
  ? {
      title: 'Santé de la stack',
      scan: 'Analyser',
      scanning: 'Analyse en cours (jusqu’à une minute)…',
      fix: 'Corriger avec un agent',
      never: 'Pas encore d’analyse pour ce projet. Analyser lit les versions de PHP, Symfony, Drupal, Sylius, Node et de la base, puis lance composer audit et npm audit. Le projet est ensuite réanalysé chaque jour.',
      versions: 'Versions',
      component: 'Composant',
      version: 'Version',
      status: 'Statut',
      latest: 'Dernière',
      ok: (d) => (d ? `supportée jusqu’au ${d}` : 'supportée'),
      soon: (d) => `fin de vie le ${d}`,
      eol: (d) => (d ? `fin de vie depuis le ${d}` : 'fin de vie'),
      unknown: 'inconnue',
      composer: (n) => `Composer : ${n} paquet${n > 1 ? 's' : ''} avec des failles connues`,
      composerOk: 'Composer : aucune faille connue',
      abandoned: 'Paquets abandonnés : ',
      npm: 'npm',
      npmOk: 'npm : aucune faille connue',
      direct: 'dépendance directe',
      nofix: 'pas de correctif',
      noVersions: 'Aucune version reconnue dans .lando.yml, composer.json, composer.lock, .nvmrc ni package.json.',
      opened: 'La fenêtre Nouvel agent est ouverte avec la liste des mises à jour.',
      at: (d) => `Analysé ${d}`,
    }
  : {
      title: 'Stack health',
      scan: 'Scan',
      scanning: 'Scanning (up to a minute)…',
      fix: 'Fix with an agent',
      never: 'No scan for this project yet. Scan reads the versions of PHP, Symfony, Drupal, Sylius, Node and the database, then runs composer audit and npm audit. The project is then scanned again every day.',
      versions: 'Versions',
      component: 'Component',
      version: 'Version',
      status: 'Status',
      latest: 'Latest',
      ok: (d) => (d ? `supported until ${d}` : 'supported'),
      soon: (d) => `end of life on ${d}`,
      eol: (d) => (d ? `end of life since ${d}` : 'end of life'),
      unknown: 'unknown',
      composer: (n) => `Composer: ${n} package${n > 1 ? 's' : ''} with known vulnerabilities`,
      composerOk: 'Composer: no known vulnerability',
      abandoned: 'Abandoned packages: ',
      npm: 'npm',
      npmOk: 'npm: no known vulnerability',
      direct: 'direct dependency',
      nofix: 'no fix',
      noVersions: 'No version found in .lando.yml, composer.json, composer.lock, .nvmrc or package.json.',
      opened: 'The New agent window is open with the list of updates.',
      at: (d) => `Scanned ${d}`,
    }

const state = { report: undefined, busy: false, error: '', note: '' }
const send = (type, extra = {}) => squadron.send({ ...extra, type, to: me, lang })

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v)
    else if (k in el) el[k] = v
    else el.setAttribute(k, v)
  }
  el.append(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false))
  return el
}

const tone = (s) => (s === 'ok' ? 'tag ok' : s === 'eol' || s === 'critical' || s === 'high' ? 'tag err' : 'tag')

function versions(r) {
  if (!r.versions.length) return h('p', { className: 'muted' }, T.noVersions)
  return h(
    'table',
    {},
    h('thead', {}, h('tr', {}, h('th', {}, T.component), h('th', {}, T.version), h('th', {}, T.status), h('th', {}, T.latest))),
    h(
      'tbody',
      {},
      r.versions.map((v) => h('tr', {}, h('td', {}, v.label), h('td', {}, v.version), h('td', {}, h('span', { className: tone(v.status) }, v.status === 'unknown' ? T.unknown : T[v.status](v.eol))), h('td', { className: 'muted' }, v.latest))),
    ),
  )
}

function composer(r) {
  if (!r.composer) return null
  if (!r.composer.length && !r.abandoned.length) return h('h3', {}, T.composerOk)
  return [
    h('h3', {}, r.composer.length ? T.composer(r.composer.length) : T.composerOk),
    r.composer.map((p) =>
      h(
        'div',
        { className: 'pkg' },
        h('strong', {}, p.name),
        ' ',
        h('span', { className: 'muted' }, p.version),
        h('ul', {}, p.advisories.map((a) => h('li', {}, a.severity && [h('span', { className: tone(a.severity) }, a.severity), ' '], a.title, a.cve && h('span', { className: 'muted' }, ` · ${a.cve}`)))),
      ),
    ),
    r.abandoned.length > 0 && h('p', { className: 'muted' }, T.abandoned + r.abandoned.map(([n, by]) => (by ? `${n} → ${by}` : n)).join(', ')),
  ]
}

function npm(r) {
  if (!r.npm) return null
  const total = r.npm.counts.reduce((n, [, c]) => n + c, 0)
  if (!total) return h('h3', {}, T.npmOk)
  return [
    h('h3', {}, T.npm),
    h('div', { className: 'counts' }, r.npm.counts.filter(([, c]) => c > 0).map(([k, c]) => h('span', { className: tone(k) }, `${c} ${k}`))),
    h('table', {}, h('tbody', {}, r.npm.packages.map((p) => h('tr', {}, h('td', {}, h('code', {}, p.name)), h('td', {}, h('span', { className: tone(p.severity) }, p.severity)), h('td', { className: 'muted' }, [p.direct && T.direct, !p.fix && T.nofix].filter(Boolean).join(' · ')))))),
  ]
}

function scan() {
  state.busy = true
  state.error = state.note = ''
  render()
  send('scan')
}

function render() {
  const r = state.report
  const issues = r && ((r.composer || []).length || r.versions.some((v) => v.status !== 'ok' && v.status !== 'unknown') || (r.npm && r.npm.counts.some(([, c]) => c > 0)))
  const status = state.busy ? T.scanning : state.note || (r ? T.at(new Date(r.at).toLocaleString(lang)) : '')
  document.getElementById('app').replaceChildren(
    ...[
      h('header', { className: 'bar' }, h('strong', {}, T.title), h('span', { className: 'status muted', role: 'status' }, status), h('button', { disabled: state.busy, onclick: scan }, T.scan), issues && h('button', { className: 'primary', disabled: state.busy, onclick: () => send('fix') }, T.fix)),
      state.error && h('p', { className: 'error' }, state.error),
      r === null && h('p', { className: 'muted empty' }, T.never),
      r && [h('h3', {}, T.versions), versions(r), composer(r), npm(r), r.notes.map((n) => h('p', { className: 'error' }, n))],
    ]
      .flat(Infinity)
      .filter(Boolean),
  )
}

squadron.on((msg) => {
  if (!msg || msg.to !== me) return
  if (msg.type === 'report') {
    state.report = msg.report
    state.busy = false
  } else if (msg.type === 'opened') state.note = T.opened
  else if (msg.type === 'error') {
    state.busy = false
    state.error = msg.message
    if (state.report === undefined) state.report = null
  }
  render()
})

render()
send('ready')
