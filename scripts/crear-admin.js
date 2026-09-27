#!/usr/bin/env node
// ════════════════════════════════════════════════════════════════════
//  Crear primer usuario admin en Neon
//  Uso: node scripts/crear-admin.js
// ════════════════════════════════════════════════════════════════════
require('dotenv').config({ path: '.env.local' });
const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');
const readline = require('readline');

const sql = neon(process.env.DATABASE_URL);

function hashPassword(plain) {
  const salt = crypto.randomUUID().replace(/-/g, '');
  let v = salt + ':' + String(plain || '');
  for (let i = 0; i < 12000; i++) v = crypto.createHash('sha256').update(v, 'utf8').digest('hex');
  return salt + '$' + v;
}

function generateId(prefix) {
  const now = new Date();
  const p = n => String(n).padStart(2, '0');
  const ts = `${now.getFullYear()}${p(now.getMonth()+1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
  return `${prefix}-${ts}-${Math.floor(Math.random() * 10000)}`;
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(r => rl.question(q, r));

(async () => {
  try {
    const existing = await sql(`SELECT COUNT(*) AS cnt FROM usuarios`);
    if (Number(existing[0].cnt) > 0) {
      console.log('Ya existen usuarios. Si querés agregar más, usá la pantalla de Config dentro de la app.');
      rl.close(); return;
    }
    console.log('\n=== Crear primer usuario admin ===\n');
    const usuario = (await ask('Usuario (ej: admin): ')).trim().toLowerCase();
    const password = (await ask('Contraseña (mínimo 12 caracteres): ')).trim();
    const nombre = (await ask('Nombre completo: ')).trim();
    const email = (await ask('Email: ')).trim();
    if (!usuario || !password || password.length < 12) { console.error('Datos inválidos'); rl.close(); return; }
    const id = generateId('USR');
    await sql(
      `INSERT INTO usuarios (id_usuario, usuario, nombre, email, password_hash, rol, activo, fecha_alta, fecha_actualizacion) VALUES ($1,$2,$3,$4,$5,'admin','SI',NOW(),NOW())`,
      [id, usuario, nombre || usuario, email, hashPassword(password)]
    );
    console.log(`\n✓ Admin creado: ${usuario} (id: ${id})`);
    console.log('Ya podés iniciar sesión en la app.\n');
  } catch (err) {
    console.error('Error:', err.message);
  } finally {
    rl.close();
  }
})();
