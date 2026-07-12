'use strict';
const fs = require('fs');
const zlib = require('zlib');
if (process.argv.length !== 4) throw new Error('Usage: node Assert-ExpandedPayloadParity.js <expected.gz> <actual.gz>');
const load = path => JSON.parse(zlib.gunzipSync(fs.readFileSync(path)));
const expand = payload => {
  const l = payload.lookups;
  return payload.vulns.map(r => {
    const d = l.devices[r[0]], c = l.cves[r[1]], s = l.software[r[2]];
    return JSON.stringify([
      d.id, d.n, l.groups[d.g] ?? null, l.platforms[d.o] ?? null, (d.t || []).map(i => l.tags[i]),
      c.id, c.sc, l.severities[c.sv] ?? null, l.exploitLevels[c.ex] ?? null, c.u, l.batchTitles[c.bt] ?? null,
      l.vendors[s.v] ?? null, s.n, s.r, l.versions[r[3]] ?? null, l.dates[r[4]] ?? null, l.dates[r[5]] ?? null,
      r[6], r[7] < 0 ? null : l.updates[r[7]], r[8] == null ? null : r[8].map(i => l.diskPaths[i]),
      r[9] == null ? null : r[9].map(i => l.regPaths[i])
    ]);
  }).sort();
};
const expected = expand(load(process.argv[2]));
const actual = expand(load(process.argv[3]));
if (expected.length !== actual.length) throw new Error(`Expanded row count differs: ${expected.length} != ${actual.length}`);
for (let i = 0; i < expected.length; i++) if (expected[i] !== actual[i]) throw new Error(`Expanded row ${i} differs.\nExpected: ${expected[i]}\nActual: ${actual[i]}`);
console.log(`Expanded payload parity passed for ${expected.length} row(s).`);
