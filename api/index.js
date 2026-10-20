'use strict';
// ════════════════════════════════════════════════════════════════════
//  Personal DMTH — API Vercel + Neon
// ════════════════════════════════════════════════════════════════════
const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

// ── DB ────────────────────────────────────────────────────────────────
function getDb() {
  if (!process.env.DATABASE_URL) throw new Error('Falta DATABASE_URL');
  return neon(process.env.DATABASE_URL);
}

// ── UTILS ─────────────────────────────────────────────────────────────
function genId(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
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
    o.cuil, o.dni, o.apellido, o.nombre,
    o.apellido_nombre, o.establecimiento,
    o.localidad, o.sector, o.tarea_puesto
  ].join(' '));
}

// ── AUTH ─────────────────────────────────────────────────────────────
function hashPassword(plain) {
  const salt = crypto.randomUUID().replace(/-/g, '');
  let v = salt + ':' + String(plain || '');
  for (let i = 0; i < 12000; i++) v = crypto.createHash('sha256').update(v, 'utf8').digest('hex');
  return salt + '$' + v;
}

function verifyPassword(plain, stored) {
  stored = String(stored || '');
  if (!stored.includes('$')) {
    return stored === crypto.createHash('sha256').update(String(plain || ''), 'utf8').digest('hex');
  }
  const [salt, hash] = stored.split('$');
  let v = salt + ':' + String(plain || '');
  for (let i = 0; i < 12000; i++) v = crypto.createHash('sha256').update(v, 'utf8').digest('hex');
  return v === hash;
}

function tokenSecret() {
  const s = process.env.DMTH_TOKEN_SECRET;
  if (!s) throw new Error('Falta DMTH_TOKEN_SECRET');
  return s;
}

function makeToken(user) {
  const payload = JSON.stringify({
    id: user.id_usuario,
    u: user.usuario,
    n: user.nombre,
    r: user.rol,
    e: user.email,
    exp: Date.now() + 8 * 60 * 60 * 1000 // 8 horas
  });
  const b64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', tokenSecret()).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const sig = crypto.createHmac('sha256', tokenSecret()).update(parts[0]).digest('base64url');
  if (sig !== parts[1]) return null;
  try {
    const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (Date.now() > data.exp) return null;
    return data;
  } catch { return null; }
}

function getToken(req) {
  const auth = req.headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

function requireAuth(req, minRol) {
  const data = verifyToken(getToken(req));
  if (!data) return null;
  const orden = ['read', 'user', 'admin', 'superadmin'];
  if (orden.indexOf(data.r) < orden.indexOf(minRol)) return null;
  return data;
}

// ── LOG ─────────────────────────────────────────────────────────────
async function log(sql, usuario, accion, entidad, id_entidad, detalle = '') {
  await sql`INSERT INTO logs (usuario, accion, entidad, id_entidad, detalle)
            VALUES (${usuario}, ${accion}, ${entidad}, ${id_entidad}, ${detalle})`;
}

// ── CORS ─────────────────────────────────────────────────────────────
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

function ok(res, data) {
  cors(res);
  res.status(200).json({ ok: true, ...data });
}

function err(res, msg, status = 400) {
  cors(res);
  res.status(status).json({ ok: false, error: msg });
}

// ════════════════════════════════════════════════════════════════════
//  HANDLER PRINCIPAL
// ════════════════════════════════════════════════════════════════════
module.exports = async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body = req.method === 'POST' ? req.body : {};
  const query = req.query || {};
  const action = body.action || query.action || '';

  try {
    const sql = getDb();

    // ─ LOGIN ──────────────────────────────────────────────────────
    if (action === 'login') {
      const { email, password } = body;
      if (!email || !password) return err(res, 'Email y contraseña requeridos');

      const rows = await sql`
        SELECT * FROM usuarios
        WHERE (email = ${email.toLowerCase()} OR usuario = ${email.toLowerCase()})
          AND activo = 'SI'
        LIMIT 1
      `;
      if (!rows.length) return err(res, 'Credenciales incorrectas', 401);

      const user = rows[0];
      if (!verifyPassword(password, user.password_hash))
        return err(res, 'Credenciales incorrectas', 401);

      await sql`UPDATE usuarios SET ultimo_login = NOW() WHERE id_usuario = ${user.id_usuario}`;
      await log(sql, user.usuario, 'LOGIN', 'usuarios', user.id_usuario);

      return ok(res, {
        token: makeToken(user),
        usuario: { id: user.id_usuario, usuario: user.usuario, nombre: user.nombre, email: user.email, rol: user.rol }
      });
    }

    // ─ VERIFY TOKEN ───────────────────────────────────────────────
    if (action === 'verifyToken') {
      const data = verifyToken(getToken(req));
      if (!data) return err(res, 'Token inválido', 401);
      return ok(res, { usuario: { id: data.id, usuario: data.u, nombre: data.n, email: data.e, rol: data.r } });
    }

    // ─ STATS DASHBOARD ────────────────────────────────────────────
    if (action === 'getStats') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);

      const [ag, os, ot] = await Promise.all([
        sql`SELECT
          COUNT(*) FILTER (WHERE activo='SI') as activos,
          COUNT(*) FILTER (WHERE activo='NO') as bajas,
          COUNT(DISTINCT establecimiento) FILTER (WHERE activo='SI') as establecimientos,
          COUNT(DISTINCT sector) FILTER (WHERE activo='SI') as sectores
        FROM agentes`,
        sql`SELECT COUNT(*) as total FROM ordenes_salida WHERE activo='SI'`,
        sql`SELECT COUNT(*) as total FROM ordenes_trabajo WHERE activo='SI'`
      ]);

      return ok(res, { stats: { agentes: ag[0], ordenes_salida: os[0], ordenes_trabajo: ot[0] } });
    }

    // ─ BUSCAR AGENTES ─────────────────────────────────────────────
    if (action === 'buscarAgentes') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);

      const q = normalizar(body.q || query.q || '');
      const filtro_activo = body.activo ?? 'SI';
      const filtro_establecimiento = body.establecimiento || '';
      const filtro_sector = body.sector || '';
      const limit = Math.min(parseInt(body.limit || query.limit || 50), 200);
      const offset = parseInt(body.offset || query.offset || 0);

      let rows;
      if (q) {
        rows = await sql`
          SELECT id_agente, cuil, dni, apellido, nombre, apellido_nombre,
                 establecimiento, sector, tarea_puesto, fecha_ingreso, activo
          FROM agentes
          WHERE (search_key ILIKE ${'%' + q + '%'})
            AND (${filtro_activo} = '' OR activo = ${filtro_activo})
            AND (${filtro_establecimiento} = '' OR establecimiento = ${filtro_establecimiento})
            AND (${filtro_sector} = '' OR sector = ${filtro_sector})
          ORDER BY apellido_nombre
          LIMIT ${limit} OFFSET ${offset}
        `;
      } else {
        rows = await sql`
          SELECT id_agente, cuil, dni, apellido, nombre, apellido_nombre,
                 establecimiento, sector, tarea_puesto, fecha_ingreso, activo
          FROM agentes
          WHERE (${filtro_activo} = '' OR activo = ${filtro_activo})
            AND (${filtro_establecimiento} = '' OR establecimiento = ${filtro_establecimiento})
            AND (${filtro_sector} = '' OR sector = ${filtro_sector})
          ORDER BY apellido_nombre
          LIMIT ${limit} OFFSET ${offset}
        `;
      }

      return ok(res, { agentes: rows, count: rows.length });
    }

    // ─ GET AGENTE ─────────────────────────────────────────────────
    if (action === 'getAgente') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);

      const { id_agente } = body.id_agente ? body : query;
      if (!id_agente) return err(res, 'Falta id_agente');

      const [agente, historial] = await Promise.all([
        sql`SELECT * FROM agentes WHERE id_agente = ${id_agente} LIMIT 1`,
        sql`SELECT * FROM historial_agente WHERE id_agente = ${id_agente} ORDER BY fecha DESC LIMIT 100`
      ]);

      if (!agente.length) return err(res, 'Agente no encontrado', 404);
      return ok(res, { agente: agente[0], historial });
    }

    // ─ CREAR AGENTE ───────────────────────────────────────────────
    if (action === 'crearAgente') {
      const auth = requireAuth(req, 'admin');
      if (!auth) return err(res, 'No autorizado', 401);

      const { cuil, dni, apellido, nombre } = body;
      if (!cuil || !dni || !apellido || !nombre)
        return err(res, 'Campos requeridos: cuil, dni, apellido, nombre');

      const id_agente = genId('ag');
      const apellido_nombre = `${apellido} ${nombre}`.toUpperCase();
      const search_key = agenteSearchKey({ ...body, id_agente, apellido_nombre });

      await sql`
        INSERT INTO agentes
          (id_agente, cuil, dni, apellido, nombre, apellido_nombre,
           telefono, email, fecha_nacimiento, foto_url,
           establecimiento, localidad, sector, tarea_puesto,
           categoria, nivel_educativo, tipo_contratacion,
           fecha_ingreso, codigo_1, codigo_2, codigo_3, codigo_4, codigo_5,
           activo, observaciones, search_key, usuario_actualizacion)
        VALUES
          (${id_agente}, ${cuil}, ${dni},
           ${apellido.toUpperCase()}, ${nombre.toUpperCase()}, ${apellido_nombre},
           ${body.telefono||''}, ${body.email||''}, ${body.fecha_nacimiento||''},
           ${body.foto_url||''}, ${body.establecimiento||''}, ${body.localidad||''},
           ${body.sector||''}, ${body.tarea_puesto||''}, ${body.categoria||''},
           ${body.nivel_educativo||''}, ${body.tipo_contratacion||''},
           ${body.fecha_ingreso||''},
           ${body.codigo_1||''}, ${body.codigo_2||''}, ${body.codigo_3||''},
           ${body.codigo_4||''}, ${body.codigo_5||''},
           'SI', ${body.observaciones||''}, ${search_key}, ${auth.u})
      `;

      await sql`
        INSERT INTO historial_agente (id, id_agente, tipo_cambio, observaciones, usuario)
        VALUES (${genId('h')}, ${id_agente}, 'ALTA', 'Alta del agente', ${auth.u})
      `;

      await log(sql, auth.u, 'CREAR_AGENTE', 'agentes', id_agente, apellido_nombre);
      return ok(res, { id_agente, mensaje: 'Agente creado correctamente' });
    }

    // ─ ACTUALIZAR AGENTE ──────────────────────────────────────────
    if (action === 'updateAgente') {
      const auth = requireAuth(req, 'admin');
      if (!auth) return err(res, 'No autorizado', 401);

      const { id_agente } = body;
      if (!id_agente) return err(res, 'Falta id_agente');

      const prev = await sql`SELECT * FROM agentes WHERE id_agente = ${id_agente} LIMIT 1`;
      if (!prev.length) return err(res, 'Agente no encontrado', 404);

      const old = prev[0];
      const campos = [
        'cuil','dni','apellido','nombre','telefono','email','fecha_nacimiento','foto_url',
        'establecimiento','localidad','sector','tarea_puesto','categoria',
        'nivel_educativo','tipo_contratacion','fecha_ingreso','fecha_baja','motivo_baja',
        'codigo_1','codigo_2','codigo_3','codigo_4','codigo_5','activo','observaciones'
      ];

      const cambios = [];
      for (const c of campos) {
        if (body[c] !== undefined && String(body[c]) !== String(old[c] ?? '')) {
          cambios.push({ campo: c, anterior: old[c] ?? '', nuevo: body[c] });
        }
      }

      if (!cambios.length) return ok(res, { mensaje: 'Sin cambios' });

      const upd = {};
      for (const c of cambios) upd[c.campo] = c.nuevo;

      const apellido_n = (upd.apellido || old.apellido).toUpperCase();
      const nombre_n = (upd.nombre || old.nombre).toUpperCase();
      const apellido_nombre = `${apellido_n} ${nombre_n}`;
      const search_key = agenteSearchKey({ ...old, ...upd, apellido_nombre });

      await sql`
        UPDATE agentes SET
          cuil = ${upd.cuil ?? old.cuil},
          dni = ${upd.dni ?? old.dni},
          apellido = ${apellido_n},
          nombre = ${nombre_n},
          apellido_nombre = ${apellido_nombre},
          telefono = ${upd.telefono ?? old.telefono},
          email = ${upd.email ?? old.email},
          fecha_nacimiento = ${upd.fecha_nacimiento ?? old.fecha_nacimiento},
          foto_url = ${upd.foto_url ?? old.foto_url},
          establecimiento = ${upd.establecimiento ?? old.establecimiento},
          localidad = ${upd.localidad ?? old.localidad},
          sector = ${upd.sector ?? old.sector},
          tarea_puesto = ${upd.tarea_puesto ?? old.tarea_puesto},
          categoria = ${upd.categoria ?? old.categoria},
          nivel_educativo = ${upd.nivel_educativo ?? old.nivel_educativo},
          tipo_contratacion = ${upd.tipo_contratacion ?? old.tipo_contratacion},
          fecha_ingreso = ${upd.fecha_ingreso ?? old.fecha_ingreso},
          fecha_baja = ${upd.fecha_baja ?? old.fecha_baja},
          motivo_baja = ${upd.motivo_baja ?? old.motivo_baja},
          codigo_1 = ${upd.codigo_1 ?? old.codigo_1},
          codigo_2 = ${upd.codigo_2 ?? old.codigo_2},
          codigo_3 = ${upd.codigo_3 ?? old.codigo_3},
          codigo_4 = ${upd.codigo_4 ?? old.codigo_4},
          codigo_5 = ${upd.codigo_5 ?? old.codigo_5},
          activo = ${upd.activo ?? old.activo},
          observaciones = ${upd.observaciones ?? old.observaciones},
          search_key = ${search_key},
          fecha_actualizacion = NOW(),
          usuario_actualizacion = ${auth.u}
        WHERE id_agente = ${id_agente}
      `;

      // Detectar tipo de cambio principal para el historial
      let tipo = 'MODIFICACION';
      if (cambios.find(c => c.campo === 'activo' && c.nuevo === 'NO')) tipo = 'BAJA';
      if (cambios.find(c => c.campo === 'activo' && c.nuevo === 'SI' && c.anterior === 'NO')) tipo = 'REINGRESO';
      if (cambios.find(c => c.campo === 'establecimiento')) tipo = 'CAMBIO_ESTABLECIMIENTO';

      for (const c of cambios) {
        await sql`
          INSERT INTO historial_agente (id, id_agente, tipo_cambio, campo_modificado, valor_anterior, valor_nuevo, usuario)
          VALUES (${genId('h')}, ${id_agente}, ${tipo}, ${c.campo}, ${c.anterior}, ${String(c.nuevo)}, ${auth.u})
        `;
      }

      await log(sql, auth.u, 'UPDATE_AGENTE', 'agentes', id_agente, JSON.stringify(cambios.map(c => c.campo)));
      return ok(res, { mensaje: 'Agente actualizado', cambios: cambios.length });
    }

    // ─ LISTAS MAESTRAS ────────────────────────────────────────────
    if (action === 'getListasMaestras') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);

      const [establecimientos, sectores] = await Promise.all([
        sql`SELECT DISTINCT establecimiento FROM agentes WHERE establecimiento != '' ORDER BY establecimiento`,
        sql`SELECT DISTINCT sector FROM agentes WHERE sector != '' ORDER BY sector`
      ]);

      return ok(res, {
        establecimientos: establecimientos.map(r => r.establecimiento),
        sectores: sectores.map(r => r.sector)
      });
    }

    // ─ ORDENES DE SALIDA ──────────────────────────────────────────
    if (action === 'getOrdenesSalida') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);

      const desde = body.desde || query.desde || '';
      const hasta = body.hasta || query.hasta || '';
      const q = normalizar(body.q || query.q || '');
      const limit = Math.min(parseInt(body.limit || query.limit || 100), 500);
      const offset = parseInt(body.offset || query.offset || 0);

      const rows = await sql`
        SELECT * FROM ordenes_salida
        WHERE activo = 'SI'
          AND (${desde} = '' OR fecha >= ${desde})
          AND (${hasta} = '' OR fecha <= ${hasta})
          AND (${q} = '' OR LOWER(apellido_nombre) LIKE ${'%' + q + '%'} OR dni LIKE ${'%' + q + '%'})
        ORDER BY fecha DESC, hora_salida DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      const total = await sql`SELECT COUNT(*) as n FROM ordenes_salida WHERE activo = 'SI'
        AND (${desde} = '' OR fecha >= ${desde})
        AND (${hasta} = '' OR fecha <= ${hasta})`;

      return ok(res, { ordenes: rows, total: parseInt(total[0].n) });
    }

    // ─ CREAR ORDEN DE SALIDA (interna, requiere auth) ─────────────
    if (action === 'crearOrdenSalida') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);

      const { dni, apellido_nombre, sector, motivo, destino, hora_salida, hora_retorno, observaciones, vehiculo } = body;
      if (!dni || !apellido_nombre || !sector || !motivo || !hora_salida)
        return err(res, 'Faltan campos requeridos');

      const id = genId('os');
      const numero = 'OS-' + Date.now().toString(36).toUpperCase();
      const fecha = new Date().toISOString().slice(0, 10);
      const tipo = motivo.startsWith('PARTICULAR') ? 'PARTICULAR' : 'OFICIAL';

      await sql`
        INSERT INTO ordenes_salida
          (id, numero_orden, fecha, hora_salida, hora_retorno, dni, apellido_nombre,
           sector, destino, motivo, vehiculo, tipo, autorizado_por, observaciones, activo, usuario_carga)
        VALUES
          (${id}, ${numero}, ${fecha}, ${hora_salida}, ${hora_retorno||''}, ${dni}, ${apellido_nombre},
           ${sector}, ${destino||''}, ${motivo}, ${vehiculo||''}, ${tipo}, ${auth.u}, ${observaciones||''}, 'SI', ${auth.u})
      `;
      await log(sql, auth.u, 'CREAR_OS', 'ordenes_salida', id, `${apellido_nombre} – ${motivo}`);
      return ok(res, { id, numero_orden: numero, mensaje: 'Orden creada' });
    }

    // ─ EDITAR ORDEN DE SALIDA (interna, requiere auth user) ──────
    if (action === 'editarOrdenAdmin') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { id, motivo, destino, hora_salida, hora_retorno, observaciones } = body;
      if (!id || !motivo || !hora_salida) return err(res, 'Faltan campos requeridos');
      const check = await sql`SELECT id, apellido_nombre FROM ordenes_salida WHERE id=${id} AND activo='SI'`;
      if (!check.length) return err(res, 'Orden no encontrada', 404);
      const tipo = motivo.startsWith('PARTICULAR') ? 'PARTICULAR' : 'OFICIAL';
      await sql`UPDATE ordenes_salida SET motivo=${motivo}, destino=${destino||''}, hora_salida=${hora_salida}, hora_retorno=${hora_retorno||''}, tipo=${tipo}, observaciones=${observaciones||''} WHERE id=${id}`;
      await log(sql, auth.u, 'EDITAR_OS', 'ordenes_salida', id, check[0].apellido_nombre);
      return ok(res, { ok: true });
    }

    // ─ BORRAR ORDEN DE SALIDA (interna, requiere auth admin) ────────
    if (action === 'borrarOrdenAdmin') {
      const auth = requireAuth(req, 'admin');
      if (!auth) return err(res, 'No autorizado', 401);
      const { id } = body;
      if (!id) return err(res, 'Falta id');
      const check = await sql`SELECT id, apellido_nombre FROM ordenes_salida WHERE id=${id} AND activo='SI'`;
      if (!check.length) return err(res, 'Orden no encontrada', 404);
      await sql`UPDATE ordenes_salida SET activo='NO' WHERE id=${id}`;
      await log(sql, auth.u, 'BORRAR_OS', 'ordenes_salida', id, check[0].apellido_nombre);
      return ok(res, { ok: true });
    }

    // ─ BUSCAR AGENTE POR DNI (público, para salida.html) ─────────
    if (action === 'buscarAgentePorDNI') {
      const dni = String(body.dni || query.dni || '').replace(/\D/g, '').trim();
      if (!dni || dni.length < 7) return err(res, 'DNI inválido');
      const rows = await sql`
        SELECT dni, apellido_nombre, establecimiento, sector
        FROM agentes
        WHERE dni = ${dni} AND activo = 'SI'
        LIMIT 1
      `;
      if (!rows.length) return ok(res, { encontrado: false });
      return ok(res, { encontrado: true, agente: rows[0] });
    }

    // ─ CREAR ORDEN DE SALIDA (pública, sin auth) ──────────────────
    if (action === 'crearOrdenSalidaPublica') {
      const { dni, apellido_nombre, sector, motivo, destino, hora_salida, hora_retorno, observaciones } = body;
      if (!dni || !apellido_nombre || !sector || !motivo || !hora_salida)
        return err(res, 'Faltan campos requeridos');

      // Limitar: max 5 envíos por DNI por día (anti-spam básico)
      const hoy = new Date().toISOString().slice(0, 10);
      const prev = await sql`SELECT COUNT(*) as n FROM ordenes_salida WHERE dni=${dni} AND fecha=${hoy}`;
      if (parseInt(prev[0].n) >= 5) return err(res, 'Límite de envíos diarios alcanzado para este DNI', 429);

      const id = genId('os');
      const numero = 'OS-' + Date.now().toString(36).toUpperCase();
      const tipo = motivo.startsWith('PARTICULAR') ? 'PARTICULAR' : 'OFICIAL';

      await sql`
        INSERT INTO ordenes_salida
          (id, numero_orden, fecha, hora_salida, hora_retorno, dni, apellido_nombre,
           sector, destino, motivo, vehiculo, tipo, autorizado_por, observaciones, activo, usuario_carga)
        VALUES
          (${id}, ${numero}, ${hoy}, ${hora_salida}, ${hora_retorno||''}, ${dni}, ${apellido_nombre},
           ${sector}, ${destino||''}, ${motivo}, '', ${tipo}, 'web_publica', ${observaciones||''}, 'SI', 'web_publica')
      `;
      return ok(res, { id, numero_orden: numero, mensaje: 'Solicitud enviada. Presentate al inspector para la firma.' });
    }

    // ─ CREAR CUADRILLA (múltiples agentes, sin auth) ───────────────
    if (action === 'crearCuadrillaPublica') {
      const { agentes, motivo, destino, hora_salida, hora_retorno, observaciones } = body;
      if (!Array.isArray(agentes) || agentes.length === 0) return err(res, 'Falta lista de agentes');
      if (!motivo || !hora_salida) return err(res, 'Faltan campos requeridos');
      if (agentes.length > 30) return err(res, 'Máximo 30 agentes por cuadrilla');

      const hoy = new Date().toISOString().slice(0, 10);
      const tipo = motivo.startsWith('PARTICULAR') ? 'PARTICULAR' : 'OFICIAL';
      const resultados = [];

      for (const ag of agentes) {
        const { dni, apellido_nombre, sector } = ag;
        if (!dni || !apellido_nombre || !sector) continue;
        const id = genId('os');
        const numero = 'OS-' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2,4).toUpperCase();
        await sql`
          INSERT INTO ordenes_salida
            (id, numero_orden, fecha, hora_salida, hora_retorno, dni, apellido_nombre,
             sector, destino, motivo, vehiculo, tipo, autorizado_por, observaciones, activo, usuario_carga)
          VALUES
            (${id}, ${numero}, ${hoy}, ${hora_salida}, ${hora_retorno||''}, ${dni}, ${apellido_nombre},
             ${sector}, ${destino||''}, ${motivo}, '', ${tipo}, 'web_publica', ${observaciones||''}, 'SI', 'web_publica')
        `;
        resultados.push({ dni, apellido_nombre, numero_orden: numero });
      }
      return ok(res, { resultados, total: resultados.length });
    }

    // ─ ÓRDENES POR DNI (público, solo lectura) ────────────────────
    if (action === 'getOrdenesPorDNI') {
      const dni = String(body.dni || query.dni || '').replace(/\D/g, '').trim();
      if (!dni || dni.length < 7) return err(res, 'DNI inválido');
      const rows = await sql`
        SELECT id, numero_orden, fecha, hora_salida, hora_retorno, motivo, destino, sector, apellido_nombre, tipo, observaciones
        FROM ordenes_salida
        WHERE dni = ${dni} AND activo = 'SI'
        ORDER BY fecha_carga DESC
        LIMIT 20
      `;
      return ok(res, { ordenes: rows });
    }

    // ─ EDITAR ORDEN PÚBLICA (solo si el DNI del cuerpo coincide) ──
    if (action === 'editarOrdenPublica') {
      const { id, dni, motivo, destino, hora_salida, hora_retorno, observaciones } = body;
      if (!id || !dni) return err(res, 'Faltan campos');
      if (!motivo || !hora_salida) return err(res, 'Faltan campos requeridos');
      // Verificar que la orden pertenece al DNI declarado
      const check = await sql`SELECT id FROM ordenes_salida WHERE id=${id} AND dni=${dni} AND activo='SI'`;
      if (!check.length) return err(res, 'Orden no encontrada o DNI incorrecto', 403);
      const tipo = motivo.startsWith('PARTICULAR') ? 'PARTICULAR' : 'OFICIAL';
      await sql`
        UPDATE ordenes_salida
        SET motivo=${motivo}, destino=${destino||''}, hora_salida=${hora_salida},
            hora_retorno=${hora_retorno||''}, tipo=${tipo}, observaciones=${observaciones||''}
        WHERE id=${id}
      `;
      return ok(res, { ok: true });
    }

    // ─ DOC TIPOS ─────────────────────────────────────────────────
    if (action === 'getDocTipos') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);
      const rows = await sql`SELECT * FROM doc_tipos WHERE activo='SI' ORDER BY orden, nombre`;
      return ok(res, { tipos: rows });
    }

    if (action === 'addDocTipo') {
      const auth = requireAuth(req, 'admin');
      if (!auth) return err(res, 'No autorizado', 401);
      const { nombre } = body;
      if (!nombre) return err(res, 'Falta nombre');
      const id = genId('dt');
      await sql`INSERT INTO doc_tipos (id, nombre, orden) VALUES (${id}, ${nombre.trim()}, 99)`;
      await log(sql, auth.u, 'ADD_DOC_TIPO', 'doc_tipos', id, nombre);
      return ok(res, { id, nombre });
    }

    if (action === 'deleteDocTipo') {
      const auth = requireAuth(req, 'admin');
      if (!auth) return err(res, 'No autorizado', 401);
      const { id } = body;
      if (!id) return err(res, 'Falta id');
      await sql`UPDATE doc_tipos SET activo='NO' WHERE id=${id}`;
      return ok(res, { ok: true });
    }

    if (action === 'getDocsAgente') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);
      const agente_id = body.agente_id || query.agente_id;
      if (!agente_id) return err(res, 'Falta agente_id');
      const docs = await sql`
        SELECT ad.*, dt.nombre as tipo_nombre
        FROM agente_documentos ad
        JOIN doc_tipos dt ON dt.id = ad.tipo_id
        WHERE ad.agente_id = ${agente_id} AND ad.activo = 'SI'
        ORDER BY dt.orden, dt.nombre`;
      const tipos = await sql`SELECT * FROM doc_tipos WHERE activo='SI' ORDER BY orden, nombre`;
      return ok(res, { docs, tipos });
    }

    if (action === 'upsertDocAgente') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { agente_id, tipo_id, estado, fecha_vto, observaciones } = body;
      if (!agente_id || !tipo_id) return err(res, 'Faltan campos');
      const existing = await sql`SELECT id FROM agente_documentos WHERE agente_id=${agente_id} AND tipo_id=${tipo_id} AND activo='SI'`;
      if (existing.length) {
        await sql`UPDATE agente_documentos SET estado=${estado||'pendiente'}, fecha_vto=${fecha_vto||''}, observaciones=${observaciones||''}, fecha_carga=NOW(), usuario_carga=${auth.u} WHERE id=${existing[0].id}`;
        await log(sql, auth.u, 'UPDATE_DOC', 'agente_documentos', existing[0].id, tipo_id);
        return ok(res, { id: existing[0].id });
      } else {
        const id = genId('adoc');
        await sql`INSERT INTO agente_documentos (id, agente_id, tipo_id, estado, fecha_vto, observaciones, usuario_carga) VALUES (${id}, ${agente_id}, ${tipo_id}, ${estado||'pendiente'}, ${fecha_vto||''}, ${observaciones||''}, ${auth.u})`;
        await log(sql, auth.u, 'ADD_DOC', 'agente_documentos', id, tipo_id);
        return ok(res, { id });
      }
    }

    // ─ ORDENES DE TRABAJO ─────────────────────────────────────────
    if (action === 'getOrdenesTrabajo') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);

      const desde = body.desde || query.desde || '';
      const hasta = body.hasta || query.hasta || '';
      const q = normalizar(body.q || query.q || '');
      const limit = Math.min(parseInt(body.limit || query.limit || 100), 500);
      const offset = parseInt(body.offset || query.offset || 0);

      const rows = await sql`
        SELECT * FROM ordenes_trabajo
        WHERE activo = 'SI'
          AND (${desde} = '' OR fecha >= ${desde})
          AND (${hasta} = '' OR fecha <= ${hasta})
          AND (${q} = '' OR LOWER(apellido_nombre) LIKE ${'%' + q + '%'} OR dni LIKE ${'%' + q + '%'})
        ORDER BY fecha DESC
        LIMIT ${limit} OFFSET ${offset}
      `;

      const total = await sql`SELECT COUNT(*) as n FROM ordenes_trabajo WHERE activo = 'SI'
        AND (${desde} = '' OR fecha >= ${desde})
        AND (${hasta} = '' OR fecha <= ${hasta})`;

      return ok(res, { ordenes: rows, total: parseInt(total[0].n) });
    }

    // ─ CUMPLEAÑOS ─────────────────────────────────────────────────
    if (action === 'getCumpleanos') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);

      const hoy = body.fecha || query.fecha || new Date().toISOString().slice(5, 10); // MM-DD
      const rows = await sql`
        SELECT id_agente, apellido_nombre, fecha_nacimiento, establecimiento, sector, foto_url
        FROM agentes
        WHERE activo = 'SI'
          AND fecha_nacimiento != ''
          AND SUBSTRING(fecha_nacimiento FROM 4 FOR 5) = ${hoy}
        ORDER BY apellido_nombre
      `;

      return ok(res, { cumpleanos: rows });
    }

    // ─ GESTIÓN DE USUARIOS (SUPERADMIN) ──────────────────────────
    if (action === 'getUsuarios') {
      const auth = requireAuth(req, 'superadmin');
      if (!auth) return err(res, 'No autorizado', 401);

      const rows = await sql`
        SELECT id_usuario, usuario, nombre, email, rol, activo, ultimo_login, fecha_alta
        FROM usuarios ORDER BY nombre
      `;
      return ok(res, { usuarios: rows });
    }

    if (action === 'crearUsuario') {
      const auth = requireAuth(req, 'superadmin');
      if (!auth) return err(res, 'No autorizado', 401);

      const { email, nombre, usuario, password, rol } = body;
      if (!email || !nombre || !usuario || !password || !rol)
        return err(res, 'Faltan campos');
      if (password.length < 12) return err(res, 'Contraseña mínimo 12 caracteres');
      if (!['superadmin','admin','user','read'].includes(rol))
        return err(res, 'Rol inválido');

      const id = genId('usr');
      await sql`
        INSERT INTO usuarios (id_usuario, usuario, nombre, email, password_hash, rol, activo)
        VALUES (${id}, ${usuario.toLowerCase()}, ${nombre}, ${email.toLowerCase()}, ${hashPassword(password)}, ${rol}, 'SI')
      `;
      await log(sql, auth.u, 'CREAR_USUARIO', 'usuarios', id, email);
      return ok(res, { id_usuario: id, mensaje: 'Usuario creado' });
    }

    if (action === 'updateUsuario') {
      const auth = requireAuth(req, 'superadmin');
      if (!auth) return err(res, 'No autorizado', 401);

      const { id_usuario, nombre, rol, activo, password } = body;
      if (!id_usuario) return err(res, 'Falta id_usuario');
      if (rol && !['superadmin','admin','user','read'].includes(rol))
        return err(res, 'Rol inválido');

      if (password) {
        if (password.length < 12) return err(res, 'Contraseña mínimo 12 caracteres');
        await sql`UPDATE usuarios SET password_hash = ${hashPassword(password)}, fecha_actualizacion = NOW() WHERE id_usuario = ${id_usuario}`;
      }

      await sql`
        UPDATE usuarios SET
          nombre = COALESCE(NULLIF(${nombre||''},''), nombre),
          rol = COALESCE(NULLIF(${rol||''},''), rol),
          activo = COALESCE(NULLIF(${activo||''},''), activo),
          fecha_actualizacion = NOW()
        WHERE id_usuario = ${id_usuario}
      `;

      await log(sql, auth.u, 'UPDATE_USUARIO', 'usuarios', id_usuario);
      return ok(res, { mensaje: 'Usuario actualizado' });
    }

    // ─ ASISTENCIAS ────────────────────────────────────────────────
    if (action === 'importarAsistencias') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      // registros: [{fecha,dni,apellido_nombre,hora_entrada,hora_salida,servicio}] — estado calculado server-side
      const { registros } = body;
      if (!Array.isArray(registros) || !registros.length) return err(res, 'Sin registros');
      if (registros.length > 1000) return err(res, 'Máximo 1000 registros por importación');

      // Cargar horarios individuales (map dni → {hora_entrada, turno24})
      const dnis = [...new Set(registros.map(r => r.dni).filter(Boolean))];
      const horarioRows = dnis.length ? await sql`SELECT dni, hora_entrada, horario_raw FROM horarios WHERE dni = ANY(${dnis}) AND activo='SI'` : [];
      const horariosMap = Object.fromEntries(horarioRows.map(h => [h.dni, {
        entrada: h.hora_entrada,
        turno24: /24\s*hs/i.test(h.horario_raw||'') || (h.hora_entrada && h.hora_entrada === (h.horario_raw||'').match(/\d{1,2}:\d{2}/g)?.[1]?.padStart(5,'0'))
      }]));

      // Cargar excepciones activas para la fecha
      const fecha0 = registros[0]?.fecha || '';
      const excRows = fecha0 ? await sql`SELECT dni, tipo FROM asistencia_excepciones WHERE activo='SI' AND fecha_desde <= ${fecha0} AND fecha_hasta >= ${fecha0}` : [];
      const excMap = Object.fromEntries(excRows.map(e => [e.dni, e.tipo]));

      let insertados = 0, actualizados = 0, errores = 0;
      for (const r of registros) {
        if (!r.fecha || !r.dni || !r.apellido_nombre) { errores++; continue; }
        const id = genId('ast');

        // Calcular tardanza usando horario individual (si existe) o sin tardanza
        let estado = 'PRESENTE', minutos_tardanza = 0;
        if (excMap[r.dni]) {
          estado = excMap[r.dni]; // VACACIONES, ART, LICENCIA, etc.
        } else if (r.hora_entrada) {
          const hor = horariosMap[r.dni];
          // Turno 24hs: no se evalúa tardanza
          if (hor && hor.entrada && !hor.turno24) {
            const [lh, lm] = hor.entrada.split(':').map(Number);
            const [eh, em] = r.hora_entrada.split(':').map(Number);
            const limMin = lh * 60 + lm;
            const entMin = eh * 60 + em;
            if (entMin > limMin + 11) { // tolerancia 11 minutos
              minutos_tardanza = entMin - limMin;
              estado = 'TARDANZA';
            }
          }
        }

        try {
          const res2 = await sql`
            INSERT INTO asistencias (id,fecha,dni,apellido_nombre,hora_entrada,hora_salida,estado,servicio,minutos_tardanza,activo,usuario_carga)
            VALUES (${id},${r.fecha},${r.dni},${r.apellido_nombre},${r.hora_entrada||''},${r.hora_salida||''},${estado},${r.servicio||''},${minutos_tardanza},'SI',${auth.u})
            ON CONFLICT (fecha,dni) DO UPDATE SET
              hora_entrada=EXCLUDED.hora_entrada, hora_salida=EXCLUDED.hora_salida,
              estado=EXCLUDED.estado, servicio=EXCLUDED.servicio,
              minutos_tardanza=EXCLUDED.minutos_tardanza,
              fecha_importacion=NOW(), usuario_carga=EXCLUDED.usuario_carga
            RETURNING (xmax=0) AS inserted
          `;
          if (res2[0]?.inserted) insertados++; else actualizados++;
        } catch (e) { errores++; }
      }
      await log(sql, auth.u, 'IMPORTAR_ASISTENCIAS', 'asistencias', fecha0, `${insertados} nuevos, ${actualizados} actualizados, ${errores} errores`);
      return ok(res, { insertados, actualizados, errores });
    }

    if (action === 'getAsistencias') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);
      const fecha = body.fecha || query.fecha || '';
      const q = normalizar(body.q || query.q || '');
      const filtroEstado = body.estado || query.estado || '';
      const limit = Math.min(parseInt(body.limit || query.limit || 200), 500);
      const offset = parseInt(body.offset || query.offset || 0);
      if (!fecha) return ok(res, { asistencias: [], total: 0, ausentes: [] });

      const rows = await sql`
        SELECT a.*, h.hora_entrada AS horario_esperado, h.horario_raw
        FROM asistencias a
        LEFT JOIN horarios h ON h.dni = a.dni AND h.activo='SI'
        WHERE a.fecha=${fecha} AND a.activo='SI'
          AND (${q}='' OR LOWER(a.apellido_nombre) LIKE ${'%'+q+'%'} OR a.dni LIKE ${'%'+q+'%'})
          AND (${filtroEstado}='' OR a.estado=${filtroEstado})
        ORDER BY a.estado DESC, a.apellido_nombre
        LIMIT ${limit} OFFSET ${offset}
      `;
      const tot = await sql`SELECT COUNT(*) as n FROM asistencias WHERE fecha=${fecha} AND activo='SI'`;

      // Ausentes del padrón: cruzar con horarios activos (solo quienes tienen horario asignado) o todos
      const ausentesRows = await sql`
        SELECT a.dni, a.apellido_nombre, a.establecimiento, a.sector,
               h.hora_entrada, h.horario_raw,
               e.tipo AS excepcion
        FROM agentes a
        LEFT JOIN horarios h ON h.dni = a.dni AND h.activo='SI'
        LEFT JOIN asistencia_excepciones e ON e.dni = a.dni AND e.activo='SI'
          AND e.fecha_desde <= ${fecha} AND e.fecha_hasta >= ${fecha}
        WHERE a.activo='SI'
          AND a.dni NOT IN (SELECT dni FROM asistencias WHERE fecha=${fecha} AND activo='SI')
        ORDER BY a.apellido_nombre
        LIMIT 500
      `;

      return ok(res, { asistencias: rows, total: parseInt(tot[0].n), ausentes: ausentesRows });
    }

    // ─ HORARIOS ──────────────────────────────────────────────────
    if (action === 'importarHorarios') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { horarios } = body;
      if (!Array.isArray(horarios) || !horarios.length) return err(res, 'Sin registros');
      if (horarios.length > 2000) return err(res, 'Máximo 2000 registros');
      let insertados = 0, actualizados = 0, errores = 0;
      for (const h of horarios) {
        if (!h.dni || !h.apellido_nombre) { errores++; continue; }
        const id = genId('hor');
        try {
          const r2 = await sql`
            INSERT INTO horarios (id,bio_id,dni,apellido_nombre,sector,servicio,hora_entrada,hora_salida,horario_raw,activo)
            VALUES (${id},${h.bio_id||''},${h.dni},${h.apellido_nombre},${h.sector||''},${h.servicio||''},${h.hora_entrada||''},${h.hora_salida||''},${h.horario_raw||''},'SI')
            ON CONFLICT (dni) DO UPDATE SET
              bio_id=EXCLUDED.bio_id, apellido_nombre=EXCLUDED.apellido_nombre,
              sector=EXCLUDED.sector, servicio=EXCLUDED.servicio,
              hora_entrada=EXCLUDED.hora_entrada, hora_salida=EXCLUDED.hora_salida,
              horario_raw=EXCLUDED.horario_raw, activo='SI', fecha_carga=NOW()
            RETURNING (xmax=0) AS inserted
          `;
          if (r2[0]?.inserted) insertados++; else actualizados++;
        } catch (e) { errores++; }
      }
      await log(sql, auth.u, 'IMPORTAR_HORARIOS', 'horarios', '', `${insertados} nuevos, ${actualizados} actualizados`);
      return ok(res, { insertados, actualizados, errores });
    }

    if (action === 'getHorarios') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);
      const q = normalizar(body.q || query.q || '');
      const rows = await sql`
        SELECT * FROM horarios WHERE activo='SI'
          AND (${q}='' OR LOWER(apellido_nombre) LIKE ${'%'+q+'%'} OR dni LIKE ${'%'+q+'%'})
        ORDER BY apellido_nombre LIMIT 500
      `;
      const tot = await sql`SELECT COUNT(*) as n FROM horarios WHERE activo='SI'`;
      return ok(res, { horarios: rows, total: parseInt(tot[0].n) });
    }

    // ─ EXCEPCIONES DE ASISTENCIA ──────────────────────────────────
    if (action === 'addExcepcion') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { dni, apellido_nombre, fecha_desde, fecha_hasta, tipo, observaciones } = body;
      if (!dni || !fecha_desde || !fecha_hasta || !tipo) return err(res, 'Faltan campos');
      const id = genId('exc');
      await sql`INSERT INTO asistencia_excepciones (id,dni,apellido_nombre,fecha_desde,fecha_hasta,tipo,observaciones,activo,usuario_carga)
        VALUES (${id},${dni},${apellido_nombre||''},${fecha_desde},${fecha_hasta},${tipo},${observaciones||''},'SI',${auth.u})`;
      await log(sql, auth.u, 'ADD_EXCEPCION', 'asistencia_excepciones', id, `${apellido_nombre} ${tipo} ${fecha_desde}→${fecha_hasta}`);
      return ok(res, { id });
    }

    if (action === 'getExcepciones') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);
      const desde = body.desde || query.desde || '';
      const hasta = body.hasta || query.hasta || '';
      const q = normalizar(body.q || query.q || '');
      const rows = await sql`
        SELECT * FROM asistencia_excepciones WHERE activo='SI'
          AND (${desde}='' OR fecha_hasta >= ${desde})
          AND (${hasta}='' OR fecha_desde <= ${hasta})
          AND (${q}='' OR LOWER(apellido_nombre) LIKE ${'%'+q+'%'} OR dni LIKE ${'%'+q+'%'})
        ORDER BY fecha_desde DESC LIMIT 200
      `;
      return ok(res, { excepciones: rows });
    }

    if (action === 'deleteExcepcion') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { id } = body;
      if (!id) return err(res, 'Falta id');
      await sql`UPDATE asistencia_excepciones SET activo='NO' WHERE id=${id}`;
      return ok(res, { ok: true });
    }

    // ─ NOVEDADES (alias completo de asistencia_excepciones con documento) ──
    if (action === 'addNovedad') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { dni, apellido_nombre, fecha_desde, fecha_hasta, tipo, observaciones, documento_url, titulo } = body;
      if (!dni || !fecha_desde || !fecha_hasta || !tipo) return err(res, 'Faltan campos obligatorios');
      const id = genId('nov');
      await sql`INSERT INTO asistencia_excepciones
        (id,dni,apellido_nombre,fecha_desde,fecha_hasta,tipo,observaciones,documento_url,titulo,activo,usuario_carga)
        VALUES (${id},${dni},${apellido_nombre||''},${fecha_desde},${fecha_hasta},${tipo},
                ${observaciones||''},${documento_url||''},${titulo||''},'SI',${auth.u})`;
      await log(sql, auth.u, 'ADD_NOVEDAD', 'asistencia_excepciones', id,
        `${apellido_nombre} | ${tipo} | ${fecha_desde}→${fecha_hasta}`);
      return ok(res, { id });
    }

    if (action === 'getNovedades') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);
      const desde = body.desde || query.desde || '';
      const hasta = body.hasta || query.hasta || '';
      const q = normalizar(body.q || query.q || '');
      const tipo = body.tipo || query.tipo || '';
      const rows = await sql`
        SELECT e.*, a.establecimiento, a.sector
        FROM asistencia_excepciones e
        LEFT JOIN agentes a ON a.dni = e.dni AND a.activo = 'SI'
        WHERE e.activo='SI'
          AND (${desde}='' OR e.fecha_hasta >= ${desde})
          AND (${hasta}='' OR e.fecha_desde <= ${hasta})
          AND (${q}='' OR LOWER(e.apellido_nombre) LIKE ${'%'+q+'%'} OR e.dni LIKE ${'%'+q+'%'})
          AND (${tipo}='' OR e.tipo = ${tipo})
        ORDER BY e.fecha_desde DESC LIMIT 300
      `;
      const tot = await sql`SELECT COUNT(*) as n FROM asistencia_excepciones WHERE activo='SI'`;
      return ok(res, { novedades: rows, total: parseInt(tot[0].n) });
    }

    if (action === 'editNovedad') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { id, fecha_desde, fecha_hasta, tipo, observaciones, documento_url, titulo } = body;
      if (!id) return err(res, 'Falta id');
      await sql`UPDATE asistencia_excepciones SET
        fecha_desde=${fecha_desde}, fecha_hasta=${fecha_hasta}, tipo=${tipo},
        observaciones=${observaciones||''}, documento_url=${documento_url||''},
        titulo=${titulo||''}
        WHERE id=${id} AND activo='SI'`;
      await log(sql, auth.u, 'EDIT_NOVEDAD', 'asistencia_excepciones', id, tipo);
      return ok(res, { ok: true });
    }

    if (action === 'deleteNovedad') {
      const auth = requireAuth(req, 'user');
      if (!auth) return err(res, 'No autorizado', 401);
      const { id } = body;
      if (!id) return err(res, 'Falta id');
      await sql`UPDATE asistencia_excepciones SET activo='NO' WHERE id=${id}`;
      await log(sql, auth.u, 'DELETE_NOVEDAD', 'asistencia_excepciones', id, '');
      return ok(res, { ok: true });
    }

    if (action === 'getNovedadesAgente') {
      const auth = requireAuth(req, 'read');
      if (!auth) return err(res, 'No autorizado', 401);
      const { dni } = body;
      if (!dni) return err(res, 'Falta DNI');
      const rows = await sql`
        SELECT * FROM asistencia_excepciones
        WHERE dni=${dni} AND activo='SI'
        ORDER BY fecha_desde DESC
      `;
      return ok(res, { novedades: rows });
    }

    // ─ LOGS ───────────────────────────────────────────────────────
    if (action === 'getLogs') {
      const auth = requireAuth(req, 'admin');
      if (!auth) return err(res, 'No autorizado', 401);

      const rows = await sql`
        SELECT * FROM logs ORDER BY timestamp DESC LIMIT 200
      `;
      return ok(res, { logs: rows });
    }

    return err(res, `Acción desconocida: ${action}`, 404);

  } catch (e) {
    console.error('[API Error]', e.message);
    return err(res, e.message, 500);
  }
};
