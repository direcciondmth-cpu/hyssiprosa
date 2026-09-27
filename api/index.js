'use strict';
// ════════════════════════════════════════════════════════════════════
//  SIPROSA · Investigación de Accidentes — API Vercel + Neon
//  Reemplaza code.gs (Google Apps Script) con idéntica interfaz de acciones.
// ════════════════════════════════════════════════════════════════════
const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

const APP_NAME = 'SIPROSA - Investigación de Accidentes';

// ── DB ────────────────────────────────────────────────────────────────
function getDb() {
  if (!process.env.DATABASE_URL) throw new Error('Falta variable de entorno DATABASE_URL');
  return neon(process.env.DATABASE_URL);
}

// ── UTILITIES ─────────────────────────────────────────────────────────
function generateId(prefix) {
  const now = new Date();
  const p = n => String(n).padStart(2, '0');
  const ts = `${now.getFullYear()}${p(now.getMonth()+1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
  return `${prefix}-${ts}-${Math.floor(Math.random() * 10000)}`;
}

function normalizar(s) {
  return String(s || '')
    .toLowerCase()
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9ñ]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function agenteSearchKey(o) {
  return normalizar([
    o.id_agente, o.cuil, o.dni, o.apellido, o.nombre,
    o.apellido_nombre, o.establecimiento, o.localidad,
    o.sector, o.tarea_puesto
  ].join(' '));
}

// ── AUTH — compatible con hashes de code.gs ───────────────────────────
function legacyHashPassword(plain) {
  return crypto.createHash('sha256').update(String(plain || ''), 'utf8').digest('hex');
}

function hashPassword(plain) {
  const salt = crypto.randomUUID().replace(/-/g, '');
  let v = salt + ':' + String(plain || '');
  for (let i = 0; i < 12000; i++) v = crypto.createHash('sha256').update(v, 'utf8').digest('hex');
  return salt + '$' + v;
}

function verifyPassword(plain, stored) {
  stored = String(stored || '');
  if (!stored.includes('$')) return stored === legacyHashPassword(plain);
  const parts = stored.split('$');
  if (parts.length !== 2) return false;
  let v = parts[0] + ':' + String(plain || '');
  for (let i = 0; i < 12000; i++) v = crypto.createHash('sha256').update(v, 'utf8').digest('hex');
  return v === parts[1];
}

function validatePassword(password) {
  if (String(password || '').length < 12) throw new Error('La contraseña debe tener al menos 12 caracteres.');
}

function tokenSecret() {
  const s = process.env.SIPROSA_TOKEN_SECRET;
  if (!s) throw new Error('Falta variable de entorno SIPROSA_TOKEN_SECRET');
  return s;
}

function hmacHex(payload) {
  return crypto.createHmac('sha256', tokenSecret()).update(payload, 'utf8').digest('hex');
}

function makeToken(user) {
  const payload = JSON.stringify({
    u: user.usuario, n: user.nombre, r: user.rol,
    e: user.email || '', exp: Date.now() + 1000 * 60 * 60 * 12
  });
  const b64 = Buffer.from(payload).toString('base64url');
  return b64 + '.' + hmacHex(b64);
}

async function validateToken(token, sql) {
  token = String(token || '');
  const parts = token.split('.');
  if (parts.length !== 2) throw new Error('Sesión vencida o inexistente. Iniciá sesión nuevamente.');
  if (hmacHex(parts[0]) !== parts[1]) throw new Error('Sesión inválida. Iniciá sesión nuevamente.');
  let payload;
  try { payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); }
  catch { throw new Error('Token malformado.'); }
  if (!payload.exp || Date.now() > Number(payload.exp)) throw new Error('Sesión vencida. Iniciá sesión nuevamente.');
  const rows = await sql(
    `SELECT * FROM usuarios WHERE activo != 'NO' AND LOWER(usuario) = LOWER($1) LIMIT 1`,
    [payload.u]
  );
  if (!rows.length) throw new Error('Usuario inactivo o inexistente');
  return publicUser(rows[0]);
}

function publicUser(u) {
  return {
    id_usuario: u.id_usuario || '',
    usuario: u.usuario || '',
    nombre: u.nombre || u.usuario || '',
    email: u.email || '',
    rol: String(u.rol || 'user').toLowerCase(),
    activo: u.activo || 'SI'
  };
}

async function logAction(accion, entidad, id, detalle, usuario, sql) {
  try {
    await sql(
      `INSERT INTO logs (timestamp, usuario, accion, entidad, id_entidad, detalle) VALUES (NOW(), $1, $2, $3, $4, $5)`,
      [usuario || '', accion, entidad, String(id || ''), String(detalle || '')]
    );
  } catch (_) {}
}

// ── USUARIOS ──────────────────────────────────────────────────────────
async function loginUsuario(usuario, password, sql) {
  usuario = String(usuario || '').trim().toLowerCase();
  password = String(password || '');
  if (!usuario || !password) throw new Error('Ingresá usuario y contraseña');

  const rows = await sql(
    `SELECT * FROM usuarios WHERE activo != 'NO' AND (LOWER(usuario) = $1 OR LOWER(email) = $1) LIMIT 1`,
    [usuario]
  );
  if (!rows.length) throw new Error('Usuario o contraseña incorrectos');
  const row = rows[0];

  if (!verifyPassword(password, row.password_hash)) throw new Error('Usuario o contraseña incorrectos');

  if (!String(row.password_hash || '').includes('$')) {
    await sql(`UPDATE usuarios SET password_hash = $1 WHERE id_usuario = $2`, [hashPassword(password), row.id_usuario]);
  }
  await sql(`UPDATE usuarios SET ultimo_login = NOW(), fecha_actualizacion = NOW() WHERE id_usuario = $1`, [row.id_usuario]);

  const user = publicUser(row);
  const token = makeToken(user);
  await logAction('login', 'Usuarios', row.id_usuario, user.usuario, user.usuario, sql);
  return { ok: true, data: { token, user } };
}

async function listarUsuarios(sql) {
  const rows = await sql(`SELECT * FROM usuarios ORDER BY fecha_alta`);
  return { ok: true, data: rows.map(publicUser) };
}

async function crearUsuario(data, sql) {
  data = data || {};
  if (!data.usuario) throw new Error('Falta usuario');
  validatePassword(data.password);
  const usuario = String(data.usuario).trim().toLowerCase();
  const email = String(data.email || '').trim().toLowerCase();

  const existing = await sql(
    `SELECT 1 FROM usuarios WHERE LOWER(usuario) = $1 OR ($2 != '' AND LOWER(email) = $2) LIMIT 1`,
    [usuario, email]
  );
  if (existing.length) throw new Error('Ya existe un usuario con ese usuario o email');

  const id = data.id_usuario || generateId('USR');
  const rol = String(data.rol || 'user').toLowerCase() === 'admin' ? 'admin' : 'user';
  await sql(
    `INSERT INTO usuarios (id_usuario, usuario, nombre, email, password_hash, rol, activo, fecha_alta, fecha_actualizacion)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())`,
    [id, usuario, data.nombre || data.usuario, data.email || '', hashPassword(data.password), rol, data.activo || 'SI']
  );
  await logAction('crearUsuario', 'Usuarios', id, usuario, '', sql);
  return { ok: true, data: { id_usuario: id, usuario, nombre: data.nombre || usuario, email: data.email || '', rol, activo: data.activo || 'SI' } };
}

async function editarUsuario(id_usuario, data, sql) {
  if (!id_usuario) throw new Error('Falta id_usuario');
  data = data || {};
  const keys = [];
  const vals = [];

  const map = { usuario: data.usuario, nombre: data.nombre, email: data.email, activo: data.activo };
  if (data.rol !== undefined) map.rol = String(data.rol).toLowerCase() === 'admin' ? 'admin' : 'user';
  Object.entries(map).forEach(([k, v]) => { if (v !== undefined) { keys.push(k); vals.push(v); } });
  if (data.password) { validatePassword(data.password); keys.push('password_hash'); vals.push(hashPassword(data.password)); }
  if (!keys.length) return { ok: true };

  const sets = keys.map((k, i) => `"${k}" = $${i + 1}`).join(', ');
  vals.push(id_usuario);
  await sql(`UPDATE usuarios SET ${sets}, fecha_actualizacion = NOW() WHERE id_usuario = $${vals.length}`, vals);
  await logAction('editarUsuario', 'Usuarios', id_usuario, '', '', sql);
  return { ok: true };
}

async function eliminarUsuario(id_usuario, sql) {
  if (!id_usuario) throw new Error('Falta id_usuario');
  await sql(`UPDATE usuarios SET activo = 'NO', fecha_actualizacion = NOW() WHERE id_usuario = $1`, [id_usuario]);
  await logAction('eliminarUsuario', 'Usuarios', id_usuario, 'Baja lógica', '', sql);
  return { ok: true };
}

// ── AGENTES ──────────────────────────────────────────────────────────
async function buscarAgentes(query, limit, sql) {
  query = String(query || '').trim();
  limit = Math.min(Number(limit || 20), 50);
  if (!query || query.length < 3) {
    return { ok: true, data: [], meta: { min_chars: 3, message: 'Escribí al menos 3 caracteres para buscar en la base de agentes.' } };
  }
  const tokens = normalizar(query).split(' ').filter(Boolean).slice(0, 5);
  const conditions = tokens.map((_, i) => `search_key LIKE $${i + 1}`).join(' AND ');
  const vals = tokens.map(t => `%${t}%`);
  vals.push(limit);

  const rows = await sql(
    `SELECT id_agente, cuil, dni, apellido_nombre, establecimiento, sector, tarea_puesto, activo
     FROM agentes WHERE activo != 'NO' AND (${conditions}) LIMIT $${vals.length}`,
    vals
  );
  return { ok: true, data: rows, meta: { indexed: true, returned: rows.length } };
}

async function getAgente(id_agente, sql) {
  if (!id_agente) throw new Error('Falta id_agente');
  const rows = await sql(`SELECT * FROM agentes WHERE id_agente = $1 LIMIT 1`, [id_agente]);
  if (!rows.length) throw new Error('Agente no encontrado: ' + id_agente);
  return { ok: true, data: rows[0] };
}

const AGENTE_COLS = ['id_agente','cuil','dni','apellido','nombre','apellido_nombre','telefono','email',
  'establecimiento','localidad','sector','tarea_puesto','fecha_ingreso',
  'codigo_1','codigo_2','codigo_3','codigo_4','codigo_5',
  'inicio_exposicion','fin_exposicion','activo','search_key','usuario_actualizacion'];

async function crearAgente(data, userEmail, sql) {
  data = data || {};
  const obj = {
    id_agente: data.id_agente || generateId('AGE'),
    cuil: data.cuil || '', dni: data.dni || '',
    apellido: data.apellido || '', nombre: data.nombre || '',
    apellido_nombre: data.apellido_nombre || ((data.apellido || '') + ' ' + (data.nombre || '')).trim(),
    telefono: data.telefono || '', email: data.email || '',
    establecimiento: data.establecimiento || '', localidad: data.localidad || '',
    sector: data.sector || '', tarea_puesto: data.tarea_puesto || '',
    fecha_ingreso: data.fecha_ingreso || '',
    codigo_1: data.codigo_1 || '', codigo_2: data.codigo_2 || '',
    codigo_3: data.codigo_3 || '', codigo_4: data.codigo_4 || '', codigo_5: data.codigo_5 || '',
    inicio_exposicion: data.inicio_exposicion || '', fin_exposicion: data.fin_exposicion || '',
    activo: data.activo || 'SI', usuario_actualizacion: userEmail
  };
  obj.search_key = agenteSearchKey(obj);

  const cols = AGENTE_COLS.filter(k => obj[k] !== undefined);
  const colStr = cols.map(k => `"${k}"`).join(', ');
  const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
  const vals = cols.map(k => obj[k] ?? '');

  await sql(
    `INSERT INTO agentes (${colStr}, fecha_alta, fecha_actualizacion) VALUES (${placeholders}, NOW(), NOW())`,
    vals
  );
  await logAction('crearAgente', 'Agentes', obj.id_agente, obj.apellido_nombre, userEmail, sql);
  return { ok: true, data: obj };
}

async function editarAgente(id_agente, data, userEmail, sql) {
  if (!id_agente) throw new Error('Falta id_agente');
  const cur = await sql(`SELECT * FROM agentes WHERE id_agente = $1 LIMIT 1`, [id_agente]);
  if (!cur.length) throw new Error('Agente no encontrado: ' + id_agente);

  const patch = Object.assign({}, data);
  delete patch.id_agente;
  const apellido = patch.apellido !== undefined ? patch.apellido : cur[0].apellido;
  const nombre = patch.nombre !== undefined ? patch.nombre : cur[0].nombre;
  if (!patch.apellido_nombre) patch.apellido_nombre = ((apellido || '') + ' ' + (nombre || '')).trim();
  patch.search_key = agenteSearchKey(Object.assign({}, cur[0], patch, { id_agente }));
  patch.usuario_actualizacion = userEmail;

  const updatable = AGENTE_COLS.filter(k => k !== 'id_agente');
  const keys = updatable.filter(k => patch[k] !== undefined);
  if (!keys.length) return { ok: true };

  const sets = keys.map((k, i) => `"${k}" = $${i + 1}`).join(', ');
  const vals = keys.map(k => patch[k]);
  vals.push(id_agente);
  await sql(`UPDATE agentes SET ${sets}, fecha_actualizacion = NOW() WHERE id_agente = $${vals.length}`, vals);
  await logAction('editarAgente', 'Agentes', id_agente, '', userEmail, sql);
  return { ok: true };
}

async function eliminarAgente(id_agente, motivo, userEmail, sql) {
  if (!id_agente) throw new Error('Falta id_agente');
  await sql(
    `UPDATE agentes SET activo = 'NO', fecha_actualizacion = NOW(), usuario_actualizacion = $1 WHERE id_agente = $2`,
    [userEmail, id_agente]
  );
  await logAction('eliminarAgente', 'Agentes', id_agente, motivo || 'Baja lógica', userEmail, sql);
  return { ok: true };
}

async function reconstruirIndiceAgentes(sql) {
  const agentes = await sql(`SELECT * FROM agentes`);
  let rebuilt = 0;
  for (const ag of agentes) {
    const sk = agenteSearchKey(ag);
    await sql(`UPDATE agentes SET search_key = $1 WHERE id_agente = $2`, [sk, ag.id_agente]);
    rebuilt++;
  }
  await logAction('reconstruirIndiceAgentes', 'Agentes', '', rebuilt + ' agentes', '', sql);
  return { ok: true, data: { filas: rebuilt, message: `search_key reconstruido para ${rebuilt} agentes.` } };
}

// ── INVESTIGACIONES ──────────────────────────────────────────────────
const INV_COLS = [
  'id_investigacion','numero_ficha','estado','usuario_carga',
  'efector','sector_area','fecha_incidente','tipo_evento',
  'circuito_inmediato_superior','circuito_direccion_establecimiento',
  'circuito_salud_ocupacional','circuito_hys_siprosa','circuito_otros','circuito_otros_texto',
  'agente_id','agente_cuil','agente_dni','agente_apellido','agente_nombre','agente_apellido_nombre',
  'agente_telefono','agente_localidad','agente_cp','agente_provincia',
  'antiguedad_empresa_anios','antiguedad_empresa_meses','antiguedad_puesto_anios','antiguedad_puesto_meses',
  'nivel','edad','horario_desde','horario_hasta','tipo_contratacion',
  'fecha_suceso','hora_suceso','numero_siniestro','tipo_lugar_suceso','medio_traslado',
  'estaba_en_puesto','era_puesto_habitual',
  'forma_accidente_codigo','forma_accidente_descripcion',
  'agente_causante_codigo','agente_causante_descripcion','agente_causante_tipo',
  'agente_material_codigo','agente_material_descripcion',
  'naturaleza_lesion_codigo','naturaleza_lesion_descripcion',
  'zona_cuerpo_codigo','zona_cuerpo_descripcion',
  'inicio_ilt','inicio_ilt_observaciones','testigos','descripcion_accidente',
  'causa_1','causa_2','causa_3','causa_4',
  'centro_medico_primera_atencion','denuncia_policial_numero','comisaria','prestador_derivado_populart',
  'accidente_domicilio_ocurrencia','accidente_localidad',
  'responsable_apellido','responsable_nombre','responsable_cargo','responsable_titulo','responsable_mp','responsable_firma',
  'recepcion_informe','dependencia','fecha_recepcion',
  'pdf_ficha_url','doc_ficha_url','pdf_art_url','doc_art_url',
  'motivo_anulacion','fecha_anulacion','usuario_anulacion','usuario_actualizacion'
];

async function buscarInvestigaciones(filters, sql) {
  filters = filters || {};
  const conditions = [];
  const vals = [];

  if (filters.estado) { vals.push(filters.estado); conditions.push(`estado = $${vals.length}`); }
  if (filters.query) {
    const q = '%' + String(filters.query).toLowerCase() + '%';
    vals.push(q);
    const p = vals.length;
    conditions.push(`(
      LOWER(COALESCE(numero_ficha,'')) LIKE $${p} OR
      LOWER(COALESCE(numero_siniestro,'')) LIKE $${p} OR
      LOWER(COALESCE(agente_cuil,'')) LIKE $${p} OR
      LOWER(COALESCE(agente_dni,'')) LIKE $${p} OR
      LOWER(COALESCE(agente_apellido_nombre,'')) LIKE $${p} OR
      LOWER(COALESCE(efector,'')) LIKE $${p} OR
      LOWER(COALESCE(sector_area,'')) LIKE $${p} OR
      LOWER(COALESCE(descripcion_accidente,'')) LIKE $${p}
    )`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = Math.min(Number(filters.limit || 200), 1000);
  vals.push(limit);

  const rows = await sql(
    `SELECT * FROM investigaciones ${where} ORDER BY fecha_carga DESC LIMIT $${vals.length}`,
    vals
  );
  return { ok: true, data: rows };
}

async function crearInvestigacion(data, userEmail, sql) {
  const id = data.id_investigacion || generateId('INV');
  const countRows = await sql(`SELECT COUNT(*) AS cnt FROM investigaciones`);
  const n = Number(countRows[0].cnt) + 1;
  const year = new Date().getFullYear();
  const numero_ficha = data.numero_ficha || `INV-${year}-${String(n).padStart(5, '0')}`;

  const obj = { id_investigacion: id, numero_ficha, estado: data.estado || 'BORRADOR', usuario_carga: data.usuario_carga || userEmail, usuario_actualizacion: userEmail };
  INV_COLS.forEach(k => { if (k !== 'id_investigacion' && k !== 'numero_ficha' && k !== 'estado' && k !== 'usuario_carga' && k !== 'usuario_actualizacion' && data[k] !== undefined) obj[k] = data[k]; });

  const keys = INV_COLS.filter(k => obj[k] !== undefined);
  const colStr = keys.map(k => `"${k}"`).join(', ');
  const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
  const vals = keys.map(k => obj[k] ?? '');

  await sql(
    `INSERT INTO investigaciones (${colStr}, fecha_carga, fecha_actualizacion) VALUES (${placeholders}, NOW(), NOW())`,
    vals
  );

  await saveChildRows('antecedentes_at_ep', data.antecedentes_at_ep, id, sql);
  await saveChildRows('antecedentes_patologicos', data.antecedentes_patologicos, id, sql);
  await saveChildRows('antecedentes_laborales', data.antecedentes_laborales, id, sql);
  await saveChildRows('medidas_correctivas', data.medidas_correctivas, id, sql);

  await logAction('crearInvestigacion', 'Investigaciones', id, numero_ficha, userEmail, sql);
  return { ok: true, data: Object.assign({ id_investigacion: id, numero_ficha }, obj) };
}

async function editarInvestigacion(id_investigacion, data, userEmail, sql) {
  if (!id_investigacion) throw new Error('Falta id_investigacion');

  const updatable = INV_COLS.filter(k => !['id_investigacion','numero_ficha','usuario_carga','fecha_carga'].includes(k));
  const keys = updatable.filter(k => data[k] !== undefined);
  if (!keys.length) {
    // Still save children
  } else {
    keys.push('usuario_actualizacion');
    const vals = keys.slice(0, -1).map(k => data[k]);
    vals.push(userEmail, id_investigacion);
    const sets = keys.slice(0, -1).map((k, i) => `"${k}" = $${i + 1}`).join(', ');
    await sql(
      `UPDATE investigaciones SET ${sets}, "usuario_actualizacion" = $${vals.length - 1}, fecha_actualizacion = NOW() WHERE id_investigacion = $${vals.length}`,
      vals
    );
  }

  await saveChildRows('antecedentes_at_ep', data.antecedentes_at_ep, id_investigacion, sql);
  await saveChildRows('antecedentes_patologicos', data.antecedentes_patologicos, id_investigacion, sql);
  await saveChildRows('antecedentes_laborales', data.antecedentes_laborales, id_investigacion, sql);
  await saveChildRows('medidas_correctivas', data.medidas_correctivas, id_investigacion, sql);

  await logAction('editarInvestigacion', 'Investigaciones', id_investigacion, '', userEmail, sql);
  return { ok: true };
}

async function eliminarInvestigacion(id_investigacion, motivo, userEmail, sql) {
  if (!id_investigacion) throw new Error('Falta id_investigacion');
  await sql(
    `UPDATE investigaciones SET estado = 'ANULADA', motivo_anulacion = $1, fecha_anulacion = NOW()::TEXT, usuario_anulacion = $2, fecha_actualizacion = NOW() WHERE id_investigacion = $3`,
    [motivo || 'Anulada desde sistema', userEmail, id_investigacion]
  );
  await logAction('eliminarInvestigacion', 'Investigaciones', id_investigacion, motivo || '', userEmail, sql);
  return { ok: true };
}

async function getInvestigacionCompleta(id_investigacion, sql) {
  const rows = await sql(`SELECT * FROM investigaciones WHERE id_investigacion = $1 LIMIT 1`, [id_investigacion]);
  if (!rows.length) throw new Error('Investigación no encontrada: ' + id_investigacion);
  const inv = rows[0];
  const [aep, ap, al, mc, f] = await Promise.all([
    sql(`SELECT * FROM antecedentes_at_ep WHERE id_investigacion = $1 AND activo != 'NO'`, [id_investigacion]),
    sql(`SELECT * FROM antecedentes_patologicos WHERE id_investigacion = $1 AND activo != 'NO'`, [id_investigacion]),
    sql(`SELECT * FROM antecedentes_laborales WHERE id_investigacion = $1 AND activo != 'NO'`, [id_investigacion]),
    sql(`SELECT * FROM medidas_correctivas WHERE id_investigacion = $1 AND activo != 'NO'`, [id_investigacion]),
    sql(`SELECT * FROM firmas WHERE id_investigacion = $1 AND activo != 'NO'`, [id_investigacion])
  ]);
  inv.antecedentes_at_ep = aep;
  inv.antecedentes_patologicos = ap;
  inv.antecedentes_laborales = al;
  inv.medidas_correctivas = mc;
  inv.firmas = f;
  return { ok: true, data: inv };
}

const CHILD_COLS = {
  antecedentes_at_ep: ['id','id_investigacion','fecha','dias_caidos','observaciones','activo'],
  antecedentes_patologicos: ['id','id_investigacion','patologia','inicio','observaciones','activo'],
  antecedentes_laborales: ['id','id_investigacion','establecimiento','tarea','desde','hasta','observaciones','activo'],
  medidas_correctivas: ['id','id_investigacion','numero_causa','medida_correctiva','fecha','ejecucion','verificacion','responsable','estado','activo']
};

async function saveChildRows(tableName, rows, idInv, sql) {
  if (!rows || !Array.isArray(rows)) return;
  await sql(`UPDATE "${tableName}" SET activo = 'NO' WHERE id_investigacion = $1 AND activo != 'NO'`, [idInv]);
  const cols = CHILD_COLS[tableName] || [];
  for (const r of rows) {
    if (!r || !Object.keys(r).length) continue;
    const obj = Object.assign({ activo: 'SI' }, r, { id: r.id || generateId('ROW'), id_investigacion: idInv });
    const insertCols = cols.filter(k => obj[k] !== undefined);
    const colStr = insertCols.map(k => `"${k}"`).join(', ');
    const placeholders = insertCols.map((_, i) => `$${i + 1}`).join(', ');
    const vals = insertCols.map(k => obj[k] ?? '');
    await sql(`INSERT INTO "${tableName}" (${colStr}) VALUES (${placeholders}) ON CONFLICT (id) DO NOTHING`, vals);
  }
}

// ── DASHBOARD ─────────────────────────────────────────────────────────
async function getDashboard(filters, sql) {
  const rows = await sql(`SELECT tipo_evento, estado FROM investigaciones`);
  return {
    ok: true, data: {
      total: rows.length,
      accidentes_trabajo: rows.filter(r => String(r.tipo_evento).toUpperCase() === 'AT').length,
      enfermedades_profesionales: rows.filter(r => String(r.tipo_evento).toUpperCase() === 'EP').length,
      borradores: rows.filter(r => String(r.estado).toUpperCase() === 'BORRADOR').length,
      anuladas: rows.filter(r => String(r.estado).toUpperCase() === 'ANULADA').length
    }
  };
}

// ── MAIN HANDLER ──────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  let sql;
  try { sql = getDb(); } catch (err) {
    return res.status(200).json({ ok: false, error: err.message });
  }

  try {
    // Parseo manual del body si el Content-Type no se envió (compat. con versiones antiguas del frontend)
    let body = req.body;
    if (!body || typeof body !== 'object') {
      try {
        const raw = typeof body === 'string' ? body : await new Promise((resolve, reject) => {
          const chunks = [];
          req.on('data', c => chunks.push(c));
          req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
          req.on('error', reject);
        });
        body = raw ? JSON.parse(raw) : {};
      } catch { body = {}; }
    }

    const params = req.query || {};
    const action = body.action || params.action;
    if (!action) throw new Error('Falta parámetro action');

    const publicActions = ['ping', 'login'];
    let authUser = null;
    if (!publicActions.includes(action)) {
      authUser = await validateToken(body.token || params.token || '', sql);
    }

    const adminActions = ['listarUsuarios','crearUsuario','editarUsuario','eliminarUsuario',
      'crearAgente','editarAgente','eliminarAgente','eliminarInvestigacion',
      'estadoIndiceAgentes','reconstruirIndiceAgentes'];
    if (adminActions.includes(action) && (!authUser || authUser.rol !== 'admin')) {
      throw new Error('No autorizado: esta acción requiere usuario admin');
    }

    const userEmail = authUser ? (authUser.email || authUser.usuario || '') : '';
    let result;

    switch (action) {
      case 'ping':
        result = { ok: true, app: APP_NAME, now: new Date().toISOString() };
        break;
      case 'login':
        result = await loginUsuario(body.usuario || body.email || params.usuario, body.password || params.password, sql);
        break;
      case 'me':
        result = { ok: true, data: { user: authUser } };
        break;

      // Usuarios
      case 'listarUsuarios':   result = await listarUsuarios(sql); break;
      case 'crearUsuario':     result = await crearUsuario(body.data || body, sql); break;
      case 'editarUsuario':    result = await editarUsuario(body.id_usuario, body.data || body, sql); break;
      case 'eliminarUsuario':  result = await eliminarUsuario(body.id_usuario, sql); break;

      // Agentes
      case 'buscarAgentes':    result = await buscarAgentes(body.query || params.query || '', Number(body.limit || params.limit || 20), sql); break;
      case 'getAgente':        result = await getAgente(body.id_agente || params.id_agente, sql); break;
      case 'crearAgente':      result = await crearAgente(body.data || body, userEmail, sql); break;
      case 'editarAgente':     result = await editarAgente(body.id_agente, body.data || body, userEmail, sql); break;
      case 'eliminarAgente':   result = await eliminarAgente(body.id_agente, body.motivo || '', userEmail, sql); break;
      case 'estadoIndiceAgentes':
        const ca = await sql(`SELECT COUNT(*) AS cnt FROM agentes WHERE activo != 'NO'`);
        result = { ok: true, data: { agentes_filas: Number(ca[0].cnt), indice_filas: Number(ca[0].cnt), actualizado: true, mensaje: 'Índice gestionado automáticamente por PostgreSQL (columna search_key).' } };
        break;
      case 'reconstruirIndiceAgentes': result = await reconstruirIndiceAgentes(sql); break;

      // Investigaciones
      case 'buscarInvestigaciones':   result = await buscarInvestigaciones(body.filters || {}, sql); break;
      case 'getInvestigacion':         result = await getInvestigacionCompleta(body.id_investigacion || params.id_investigacion, sql); break;
      case 'crearInvestigacion':       result = await crearInvestigacion(body.data || body, userEmail, sql); break;
      case 'editarInvestigacion':      result = await editarInvestigacion(body.id_investigacion, body.data || body, userEmail, sql); break;
      case 'eliminarInvestigacion':    result = await eliminarInvestigacion(body.id_investigacion, body.motivo || '', userEmail, sql); break;

      // Dashboard
      case 'getDashboard':  result = await getDashboard(body.filters || {}, sql); break;

      // Config
      case 'getConfig': {
        const cfgRows = await sql(`SELECT clave, valor, descripcion FROM config WHERE clave != 'api_secret'`);
        const cfg = {};
        cfgRows.forEach(r => { cfg[r.clave] = r.valor; });
        result = { ok: true, config: cfg };
        break;
      }
      case 'setupSistema':
        result = { ok: true, message: 'Sistema Neon/Vercel activo. Ejecutá migrations/001_schema.sql en Neon para inicializar.' };
        break;

      // PDF — no implementado aún (requiere reemplazar Google Docs)
      case 'generarPdfFichaInterna':
      case 'generarPdfART':
        result = { ok: false, error: 'Generación de PDF no disponible aún en esta versión Vercel+Neon. Próximamente.' };
        break;

      default:
        throw new Error('Acción no reconocida: ' + action);
    }

    return res.status(200).json(result);
  } catch (err) {
    return res.status(200).json({ ok: false, error: String(err && err.message ? err.message : err) });
  }
};
