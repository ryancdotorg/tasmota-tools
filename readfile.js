const fs = require('fs');
const files = process.argv.slice(2);
if (!files.length) { files.push(0); }

for (const file of files) {
  const label = typeof file === 'number' ? 'STDIN' : file;
  try {
    const data = fs.readFileSync(file, 'utf-8');
    const fingerprint = tasmota_tls_fingerprint(data);
    console.log(`${label}: ${fingerprint}`);
  } catch (e) {
    console.log(`${label}: ${e}`);
  }
}
