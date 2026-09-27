/**
 * setup-pwa.js — crea icon-192.png desde el logo base64 del HTML
 * y verifica que los archivos PWA estén listos.
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const htmlPath = path.join(root, 'index.html');
const html = fs.readFileSync(htmlPath, 'utf8');

// Extraer el PNG base64 del login logo
const m = html.match(/src="data:image\/png;base64,([A-Za-z0-9+/=]+)"/);
if (!m) { console.error('❌ Logo PNG no encontrado en index.html'); process.exit(1); }

const buf = Buffer.from(m[1], 'base64');
fs.writeFileSync(path.join(root, 'icon-192.png'), buf);
console.log('✓ icon-192.png guardado —', buf.length, 'bytes');

// Verificar los demás archivos
['manifest.json','sw.js','favicon.svg'].forEach(f => {
  const ok = fs.existsSync(path.join(root, f));
  console.log((ok ? '✓' : '❌'), f);
});
console.log('Listo.');
