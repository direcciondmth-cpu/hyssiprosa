#!/usr/bin/env node
// ════════════════════════════════════════════════════════════════════
//  Importar agentes desde agentes_siprosa.xlsx → Neon PostgreSQL
//  Uso: node scripts/importar-agentes.js
// ════════════════════════════════════════════════════════════════════
require('dotenv').config({ path: '.env.local' });
const { neon } = require('@neondatabase/serverless');
const XLSX = require('xlsx');
const path = require('path');

const sql = neon(process.env.DATABASE_URL);
const BATCH = 50; // filas por INSERT batch

function normalizar(str) {
  return String(str || '').toLowerCase()
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function excelDateToString(val) {
  if (!val) return '';
  if (typeof val === 'string') {
    const clean = val.replace(/[\s/]/g, '');
    return clean.length > 0 ? val.trim() : '';
  }
  if (typeof val === 'number') {
    // Convertir serial de Excel a fecha
    const date = XLSX.SSF.parse_date_code(val);
    if (!date) return '';
    const y = date.y;
    const m = String(date.m).padStart(2, '0');
    const d = String(date.d).padStart(2, '0');
    return `${d}/${m}/${y}`;
  }
  return '';
}

function str(v) { return String(v == null ? '' : v).trim(); }

async function run() {
  if (!process.env.DATABASE_URL) { console.error('Falta DATABASE_URL en .env.local'); process.exit(1); }

  console.log('Leyendo Excel...');
  const wb = XLSX.readFile(path.join(__dirname, '..', 'agentes_siprosa.xlsx'));
  const ws = wb.Sheets[wb.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(ws); // usa fila 1 como header

  console.log(`Total filas: ${rows.length}`);

  // Verificar cuántos agentes ya hay
  const existing = await sql('SELECT COUNT(*) AS cnt FROM agentes');
  const cnt = Number(existing[0].cnt);
  if (cnt > 0) {
    console.log(`Ya hay ${cnt} agentes en la base. Saliendo (no sobrescribe).`);
    console.log('Si querés reimportar, ejecutá primero: DELETE FROM agentes;');
    process.exit(0);
  }

  // Deduplicar en memoria: CUIL+Establecimiento+Sector+Tarea+Codigo1
  const seen = new Map();
  for (const r of rows) {
    const k = String(r['CUIL']||r['ID_AGENTE']||'') + '|' +
              String(r['Establecimiento']||'') + '|' +
              String(r['Sector']||'') + '|' +
              String(r['Tarea/Puesto']||'') + '|' +
              String(r['Código 1']||r['Codigo 1']||'');
    if (!seen.has(k)) seen.set(k, r);
  }
  const uniqueRows = Array.from(seen.values());
  console.log(`Deduplicadas: ${rows.length} → ${uniqueRows.length} filas únicas`);

  // Contar cuántas veces aparece cada CUIL para generar IDs únicos
  const cuilCount = {};
  for (const r of uniqueRows) {
    const c = String(r['CUIL']||r['ID_AGENTE']||'').trim();
    cuilCount[c] = (cuilCount[c]||0) + 1;
  }
  const cuilIdx = {};

  let inserted = 0, errors = 0;
  const total = uniqueRows.length;

  for (let i = 0; i < total; i += BATCH) {
    const batch = uniqueRows.slice(i, i + BATCH);
    const placeholders = [];
    const values = [];
    let p = 1;

    for (const row of batch) {
      const cuil = str(row['CUIL'] || row['ID_AGENTE'] || '');
      const dni  = str(row['DNI'] || '');
      const apellido_nombre = str(row['Apellido y Nombre'] || '');
      // Separar apellido y nombre: primera palabra = apellido (aproximado)
      const partes = apellido_nombre.split(' ');
      const apellido = partes[0] || '';
      const nombre   = partes.slice(1).join(' ');
      const establecimiento = str(row['Establecimiento'] || '');
      const localidad       = str(row['Localidad'] || '');
      const sector          = str(row['Sector'] || '');
      const tarea_puesto    = str(row['Tarea/Puesto'] || '');
      const fecha_ingreso   = excelDateToString(row['Fecha ingreso']);
      const codigo_1        = str(row['Código 1'] || '');
      const codigo_2        = str(row['Código 2'] || '');
      const codigo_3        = str(row['Código 3'] || '');
      const codigo_4        = str(row['Código 4'] || '');
      const codigo_5        = str(row['Código 5'] || '');
      const inicio_exp      = excelDateToString(row['Inicio Exposición']);
      const fin_exp         = excelDateToString(row['Fin Exposición']);

      // id_agente único: si el CUIL aparece varias veces, numerar
      cuilIdx[cuil] = (cuilIdx[cuil]||0) + 1;
      const id_agente = cuil
        ? (cuilCount[cuil] > 1 ? `AGT-${cuil}-${cuilIdx[cuil]}` : `AGT-${cuil}`)
        : `AGT-${Date.now()}-${Math.random().toString(36).slice(2,6)}`;
      const search_key = normalizar(
        `${apellido_nombre} ${cuil} ${dni} ${establecimiento} ${localidad}`
      );

      placeholders.push(
        `($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},NOW(),NOW())`
      );
      values.push(
        id_agente, cuil, dni, apellido, nombre, apellido_nombre,
        '', // telefono
        '', // email
        establecimiento, localidad, sector, tarea_puesto,
        fecha_ingreso, codigo_1, codigo_2, codigo_3, codigo_4, codigo_5,
        search_key
      );
    }

    try {
      await sql(
        `INSERT INTO agentes
          (id_agente,cuil,dni,apellido,nombre,apellido_nombre,telefono,email,
           establecimiento,localidad,sector,tarea_puesto,
           fecha_ingreso,codigo_1,codigo_2,codigo_3,codigo_4,codigo_5,
           search_key,fecha_alta,fecha_actualizacion)
         VALUES ${placeholders.join(',')}
         ON CONFLICT (id_agente) DO NOTHING`,
        values
      );
      inserted += batch.length;
    } catch (err) {
      errors += batch.length;
      console.error(`\nERROR en fila ${i}: ${err.message.substring(0, 100)}`);
    }

    // Progreso
    if ((i / BATCH) % 10 === 0 || i + BATCH >= total) {
      const pct = Math.min(100, Math.round(((i + batch.length) / total) * 100));
      process.stdout.write(`\r  ${pct}% (${inserted} insertados, ${errors} errores)   `);
    }
  }

  console.log(`\n\n✓ Importación completa: ${inserted} agentes insertados, ${errors} errores`);
}

run().catch(e => { console.error(e.message); process.exit(1); });
