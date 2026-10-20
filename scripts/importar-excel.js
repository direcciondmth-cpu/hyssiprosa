'use strict';
// Importar agentes desde los 3 Excel de DMTH
// Ejecutar: node --env-file=.env.local scripts/importar-excel.js [--dry-run]

const { Pool } = require('@neondatabase/serverless');
const XLSX = require('xlsx');
const crypto = require('crypto');
const path = require('path');

const DRY_RUN = process.argv.includes('--dry-run');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const ARCHIVOS = {
  nomina: 'C:\\Users\\minsalud\\Desktop\\NOMINA PERSONAL 2026.xlsx',
  mantenimiento: 'C:\\Users\\minsalud\\Desktop\\NOMINA 2026 DIR. MANTENIMIENTO.xlsx',
  cooperativa: 'C:\\Users\\minsalud\\Desktop\\personal cooperativa.xlsx',
};

function genId(dni) { return 'dmth_' + dni; }

function norm(s) {
  return String(s || '').trim().toUpperCase().replace(/\s+/g, ' ');
}

function normName(s) {
  return String(s || '').trim().replace(/\s+/g, ' ');
}

function parseDNI(v) {
  return String(v || '').replace(/\D/g, '').trim();
}

// ── LEER NOMINA PERSONAL 2026 ─────────────────────────────────────
// Cols: [0, num, DNI, APELLIDO Y NOMBRE, PLANTA, ORGANISMO, SERVICIO, SECTOR, FUNCION, FUNCION REAL, NIVEL, LD, DOMICILIO, EMAIL, TEL, HORARIO]
function leerNominaPersonal() {
  const wb = XLSX.readFile(ARCHIVOS.nomina);
  const ws = wb.Sheets['Hoja2'];
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
  const agentes = [];
  for (const row of rows) {
    const num = row[1];
    if (!num || typeof num !== 'number') continue;
    const dni = parseDNI(row[2]);
    if (!dni || dni.length < 7) continue;
    const apellidoNombre = normName(row[3]);
    const partes = apellidoNombre.split(' ');
    // El primer apellido suele ser la primera palabra — simplificado
    const planta = norm(row[4]);
    const organismo = norm(row[5]);
    const servicio = norm(row[6]);
    const sector = norm(row[7]);
    const funcion = norm(row[8]);
    const funcionReal = norm(row[9]);
    const nivel = norm(row[10]);
    const domicilio = normName(row[12]);
    const email = String(row[13] || '').trim().toLowerCase();
    const tel = String(row[14] || '').replace(/\D/g, '');

    let tipoContratacion = 'PLANTA PERMANENTE';
    if (planta.includes('CONTRATADO')) tipoContratacion = 'CONTRATADO';

    agentes.push({
      fuente: 'nomina_personal',
      dni,
      apellido_nombre: apellidoNombre,
      apellido: partes[0] || '',
      nombre: partes.slice(1).join(' ') || '',
      establecimiento: servicio || organismo,
      sector,
      tarea_puesto: funcionReal || funcion,
      categoria: nivel,
      tipo_contratacion: tipoContratacion,
      domicilio,
      email,
      telefono: tel,
      activo: 'SI',
    });
  }
  return agentes;
}

// ── LEER NOMINA DIR. MANTENIMIENTO ────────────────────────────────
// Estructura: fila de sector como separador (col0='', col1='', col2=SECTOR_NAME)
// Filas de agente: [N, DNI, LD, APELLIDO, NOMBRE, TAREA, SECTOR]
function leerNominaMantenimiento() {
  const wb = XLSX.readFile(ARCHIVOS.mantenimiento);
  const ws = wb.Sheets['Hoja1'];
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
  const agentes = [];
  let sectorActual = 'DIRECCION DE MANTENIMIENTO';

  for (const row of rows) {
    // Fila separador de sector
    if (row[0] === '' && row[1] === '' && String(row[2]).trim() && row[2] !== 'DNI') {
      sectorActual = norm(row[2]);
      continue;
    }
    // Fila de agente
    if (typeof row[0] !== 'number' || row[0] <= 0) continue;
    const dni = parseDNI(row[1]);
    if (!dni || dni.length < 7) continue;

    const apellido = normName(row[3]);
    const nombre = normName(row[4]);
    const tarea = norm(row[5]);
    const sectorFila = norm(row[6]) || sectorActual;

    agentes.push({
      fuente: 'mantenimiento',
      dni,
      apellido_nombre: `${apellido} ${nombre}`.trim(),
      apellido,
      nombre,
      establecimiento: 'DIRECCION DE MANTENIMIENTO',
      sector: sectorFila || sectorActual,
      tarea_puesto: tarea,
      categoria: '',
      tipo_contratacion: 'PLANTA PERMANENTE',
      domicilio: '',
      email: '',
      telefono: '',
      activo: 'SI',
    });
  }
  return agentes;
}

// ── LEER COOPERATIVA ──────────────────────────────────────────────
// Cols: [N°, APELLIDO, NOMBRE, DNI, Area, Efector]
function leerCooperativa() {
  const wb = XLSX.readFile(ARCHIVOS.cooperativa);
  const ws = wb.Sheets['DPTO MOVILES EP'];
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
  const agentes = [];
  for (const row of rows) {
    if (typeof row[0] !== 'number' || row[0] <= 0) continue;
    const apellido = normName(row[1]);
    const nombre = normName(row[2]);
    const dni = parseDNI(row[3]);
    if (!dni || dni.length < 7) continue;
    const area = norm(row[4]);
    const efector = norm(row[5]);

    agentes.push({
      fuente: 'cooperativa',
      dni,
      apellido_nombre: `${apellido} ${nombre}`.trim(),
      apellido,
      nombre,
      establecimiento: area || 'Dir Gral Infraestructura',
      sector: efector,
      tarea_puesto: '',
      categoria: '',
      tipo_contratacion: 'CONTRATADO',
      domicilio: '',
      email: '',
      telefono: '',
      activo: 'SI',
    });
  }
  return agentes;
}

// ── UNIFICAR: prioridad nomina_personal > mantenimiento > cooperativa ─
function unificar(todos) {
  const map = new Map(); // dni -> agente

  // Insertar por prioridad: nomina primero, luego completar con las otras
  const orden = ['nomina_personal', 'mantenimiento', 'cooperativa'];
  for (const fuente of orden) {
    for (const a of todos.filter(x => x.fuente === fuente)) {
      if (!map.has(a.dni)) {
        map.set(a.dni, { ...a });
      } else {
        // Completar campos vacíos con los de esta fuente
        const existing = map.get(a.dni);
        for (const k of Object.keys(a)) {
          if (!existing[k] && a[k]) existing[k] = a[k];
        }
      }
    }
  }
  return [...map.values()];
}

// ── MAIN ──────────────────────────────────────────────────────────
async function main() {
  console.log('\n── Leyendo archivos Excel ────────────────────────────────\n');

  const nomina = leerNominaPersonal();
  const mant = leerNominaMantenimiento();
  const coop = leerCooperativa();

  console.log(`  NOMINA PERSONAL 2026:       ${nomina.length} agentes`);
  console.log(`  NOMINA DIR. MANTENIMIENTO:  ${mant.length} agentes`);
  console.log(`  COOPERATIVA:                ${coop.length} agentes`);

  const todos = unificar([...nomina, ...mant, ...coop]);
  console.log(`\n  Unificados (por DNI único): ${todos.length} agentes`);

  if (DRY_RUN) {
    console.log('\n── DRY RUN — primeros 5 agentes a importar:\n');
    todos.slice(0, 5).forEach(a => console.log(' ', JSON.stringify(a)));
    console.log('\n(Nada fue guardado. Quitá --dry-run para importar.)\n');
    await pool.end();
    process.exit(0);
  }

  console.log('\n── Importando a Neon ─────────────────────────────────────\n');
  let ok = 0, skip = 0, err = 0;

  for (const a of todos) {
    const id = genId(a.dni);
    const search_key = `${a.apellido_nombre} ${a.dni} ${a.cuil || ''} ${a.establecimiento} ${a.sector}`.toLowerCase();
    try {
      const res = await pool.query(`
        INSERT INTO agentes (
          id_agente, dni, apellido, nombre, apellido_nombre,
          establecimiento, sector, tarea_puesto, categoria, tipo_contratacion,
          domicilio, email, telefono, activo, search_key,
          fecha_alta, fecha_actualizacion, usuario_actualizacion
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW(),NOW(),$16)
        ON CONFLICT (id_agente) DO UPDATE SET
          apellido = EXCLUDED.apellido,
          nombre = EXCLUDED.nombre,
          apellido_nombre = EXCLUDED.apellido_nombre,
          establecimiento = COALESCE(NULLIF(EXCLUDED.establecimiento,''), agentes.establecimiento),
          sector = COALESCE(NULLIF(EXCLUDED.sector,''), agentes.sector),
          tarea_puesto = COALESCE(NULLIF(EXCLUDED.tarea_puesto,''), agentes.tarea_puesto),
          categoria = COALESCE(NULLIF(EXCLUDED.categoria,''), agentes.categoria),
          tipo_contratacion = COALESCE(NULLIF(EXCLUDED.tipo_contratacion,''), agentes.tipo_contratacion),
          domicilio = COALESCE(NULLIF(EXCLUDED.domicilio,''), agentes.domicilio),
          email = COALESCE(NULLIF(EXCLUDED.email,''), agentes.email),
          telefono = COALESCE(NULLIF(EXCLUDED.telefono,''), agentes.telefono),
          search_key = EXCLUDED.search_key,
          fecha_actualizacion = NOW(),
          usuario_actualizacion = EXCLUDED.usuario_actualizacion
        RETURNING (xmax = 0) AS inserted
      `, [
        id, a.dni, a.apellido, a.nombre, a.apellido_nombre,
        a.establecimiento, a.sector, a.tarea_puesto, a.categoria || '', a.tipo_contratacion || '',
        a.domicilio || '', a.email, a.telefono, a.activo, search_key,
        `importacion_${a.fuente}`
      ]);
      if (res.rows[0]?.inserted) ok++;
      else skip++;
      process.stdout.write(`\r  ✓ ${ok} importados, ${skip} ya existían, ${err} errores`);
    } catch (e) {
      if (e.message?.includes('duplicate') || e.message?.includes('unique')) {
        skip++;
      } else {
        err++;
        console.error(`\n  ✗ ${a.apellido_nombre} (${a.dni}): ${e.message}`);
      }
    }
  }

  console.log(`\n\n── Resultado ─────────────────────────────────────────────`);
  console.log(`  ✓ Importados:   ${ok}`);
  console.log(`  ~ Ya existían:  ${skip}`);
  console.log(`  ✗ Errores:      ${err}`);
  console.log(`  Total:          ${todos.length}\n`);

  await pool.end();
  process.exit(0);
}

main().catch(e => { console.error('\nError fatal:', e.message); process.exit(1); });
