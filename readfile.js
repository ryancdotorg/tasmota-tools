// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR MIT-0
// Copyright (c) 2024 Ryan Castellucci, No Rights Reserved
const fs = require('fs');
const files = process.argv.slice(2);
// read stdin if no filenames were provided
if (!files.length) { files.push(0); }
for (const file of files) {
  const label = files.length > 1 ? (typeof file === 'number' ? 'STDIN: ' : `${file}: `) : '';
  try {
    const data = fs.readFileSync(file, 'utf-8');
    let fingerprint = tasmota_tls_fingerprint(data);
    fingerprint += ' (Tasmota v8.4.0+)'
    console.log(label + fingerprint);
  } catch (e) {
    console.log(label + e.stack);
  }
}
