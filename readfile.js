// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR MIT-0
// Copyright (c) 2024 Ryan Castellucci, No Rights Reserved
const fs = require('fs');
const files = process.argv.slice(2);
// read stdin if no filenames were provided
if (!files.length) { files.push(0); }
for (const file of files) {
  const label = typeof file === 'number' ? 'STDIN' : file;
  try {
    const data = fs.readFileSync(file, 'utf-8');
    const fingerprint = tasmota_tls_fingerprint(data);
    console.log(`${label}: ${fingerprint}`);
  } catch (e) {
    console.log(`${label}: ${e.stack}`);
  }
}
