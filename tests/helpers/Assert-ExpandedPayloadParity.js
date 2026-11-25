'use strict';
const fs = require('fs');
const zlib = require('zlib');
if (process.argv.length !== 4) throw new Error('Usage: node Assert-ExpandedPayloadParity.js <expected.gz> <actual.gz>');
const load = path => JSON.parse(zlib.gunzipSync(fs.readFileSync(path)));
// Representation-only differences between the in-process and compiled normalizers that the dashboard
// already normalizes on load: device users may be a scalar string or null/absent, NVD weaknesses may be a
// scalar string, and an empty NVD required action may be '' or null.
const toArray = v => (v === null || v === undefined) ? null : (Array.isArray(v) ? v : [v]);
const machine = m => {
  if (!m) return null;
  const users = toArray(m.u);
  return [m.ip ?? null, m.eip ?? null, users && users.length > 0 ? users : null, m.hs ?? null, m.rs ?? null, m.el ?? null, m.dv ?? null, m.mb ?? null, m.aad ?? null, m.ls ?? null, m.fs ?? null];
};
const expand = payload => {
  const l = payload.lookups;
  const at = (arr, i) => (i === null || i === undefined || i < 0 || !arr) ? null : (arr[i] ?? null);
  return payload.vulns.map(r => {
    const d = l.devices[r[0]], c = l.cves[r[1]], s = l.software[r[2]];
    const weaknesses = toArray(c.nw);
    return JSON.stringify([
      d.id, d.n, l.groups[d.g] ?? null, l.platforms[d.o] ?? null, d.ov ?? null, (d.t || []).map(i => l.tags[i]), machine(d.m),
      c.id, c.sc, l.severities[c.sv] ?? null, l.exploitLevels[c.ex] ?? null, c.u, l.batchTitles[c.bt] ?? null,
      c.pd ?? null, c.desc ?? null, c.ep ?? null, c.as ? c.as.map(i => at(l.affSoftware, i)) : null, c.ea ?? null,
      c.nlm ?? null, c.nbs ?? null, c.nsv ?? null, c.nvec ?? null, c.nkev ?? null, c.ndu ?? null, c.nact || null,
      weaknesses && weaknesses.length > 0 ? weaknesses : null,
      l.vendors[s.v] ?? null, s.n, s.r, l.versions[r[3]] ?? null, l.dates[r[4]] ?? null, l.dates[r[5]] ?? null,
      r[6], r[7] < 0 ? null : l.updates[r[7]], r[8] == null ? null : r[8].map(i => l.diskPaths[i]),
      r[9] == null ? null : r[9].map(i => l.regPaths[i]), r.length > 10 ? at(l.inventory, r[10]) : null
    ]);
  }).sort();
};
const expected = expand(load(process.argv[2]));
const actual = expand(load(process.argv[3]));
if (expected.length !== actual.length) throw new Error(`Expanded row count differs: ${expected.length} != ${actual.length}`);
for (let i = 0; i < expected.length; i++) if (expected[i] !== actual[i]) throw new Error(`Expanded row ${i} differs.\nExpected: ${expected[i]}\nActual: ${actual[i]}`);
console.log(`Expanded payload parity passed for ${expected.length} row(s).`);