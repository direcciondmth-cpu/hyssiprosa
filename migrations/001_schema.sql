-- ════════════════════════════════════════════════════════════════════
--  SIPROSA · Investigación de Accidentes — Schema inicial (Neon / PostgreSQL)
--  Ejecutar una sola vez desde Neon Dashboard → SQL Editor
-- ════════════════════════════════════════════════════════════════════

-- ── Config ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS config (
  clave TEXT PRIMARY KEY,
  valor TEXT DEFAULT '',
  descripcion TEXT DEFAULT '',
  fecha_actualizacion TIMESTAMPTZ DEFAULT NOW()
);

-- ── Usuarios ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usuarios (
  id_usuario TEXT PRIMARY KEY,
  usuario TEXT UNIQUE NOT NULL,
  nombre TEXT DEFAULT '',
  email TEXT DEFAULT '',
  password_hash TEXT DEFAULT '',
  rol TEXT DEFAULT 'user',
  activo TEXT DEFAULT 'SI',
  ultimo_login TIMESTAMPTZ,
  fecha_alta TIMESTAMPTZ DEFAULT NOW(),
  fecha_actualizacion TIMESTAMPTZ DEFAULT NOW()
);

-- ── Agentes ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agentes (
  id_agente TEXT PRIMARY KEY,
  cuil TEXT DEFAULT '',
  dni TEXT DEFAULT '',
  apellido TEXT DEFAULT '',
  nombre TEXT DEFAULT '',
  apellido_nombre TEXT DEFAULT '',
  telefono TEXT DEFAULT '',
  email TEXT DEFAULT '',
  establecimiento TEXT DEFAULT '',
  localidad TEXT DEFAULT '',
  sector TEXT DEFAULT '',
  tarea_puesto TEXT DEFAULT '',
  fecha_ingreso TEXT DEFAULT '',
  codigo_1 TEXT DEFAULT '',
  codigo_2 TEXT DEFAULT '',
  codigo_3 TEXT DEFAULT '',
  codigo_4 TEXT DEFAULT '',
  codigo_5 TEXT DEFAULT '',
  inicio_exposicion TEXT DEFAULT '',
  fin_exposicion TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI',
  search_key TEXT DEFAULT '',
  fecha_alta TIMESTAMPTZ DEFAULT NOW(),
  fecha_actualizacion TIMESTAMPTZ DEFAULT NOW(),
  usuario_actualizacion TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_agentes_search ON agentes (search_key text_pattern_ops);
CREATE INDEX IF NOT EXISTS idx_agentes_activo ON agentes (activo);
CREATE INDEX IF NOT EXISTS idx_agentes_cuil ON agentes (cuil);
CREATE INDEX IF NOT EXISTS idx_agentes_dni ON agentes (dni);

-- ── Investigaciones ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS investigaciones (
  id_investigacion TEXT PRIMARY KEY,
  numero_ficha TEXT DEFAULT '',
  estado TEXT DEFAULT 'BORRADOR',
  fecha_carga TIMESTAMPTZ DEFAULT NOW(),
  usuario_carga TEXT DEFAULT '',
  efector TEXT DEFAULT '',
  sector_area TEXT DEFAULT '',
  fecha_incidente TEXT DEFAULT '',
  tipo_evento TEXT DEFAULT '',
  circuito_inmediato_superior TEXT DEFAULT '',
  circuito_direccion_establecimiento TEXT DEFAULT '',
  circuito_salud_ocupacional TEXT DEFAULT '',
  circuito_hys_siprosa TEXT DEFAULT '',
  circuito_otros TEXT DEFAULT '',
  circuito_otros_texto TEXT DEFAULT '',
  agente_id TEXT DEFAULT '',
  agente_cuil TEXT DEFAULT '',
  agente_dni TEXT DEFAULT '',
  agente_apellido TEXT DEFAULT '',
  agente_nombre TEXT DEFAULT '',
  agente_apellido_nombre TEXT DEFAULT '',
  agente_telefono TEXT DEFAULT '',
  agente_localidad TEXT DEFAULT '',
  agente_cp TEXT DEFAULT '',
  agente_provincia TEXT DEFAULT '',
  antiguedad_empresa_anios TEXT DEFAULT '',
  antiguedad_empresa_meses TEXT DEFAULT '',
  antiguedad_puesto_anios TEXT DEFAULT '',
  antiguedad_puesto_meses TEXT DEFAULT '',
  nivel TEXT DEFAULT '',
  edad TEXT DEFAULT '',
  horario_desde TEXT DEFAULT '',
  horario_hasta TEXT DEFAULT '',
  tipo_contratacion TEXT DEFAULT '',
  fecha_suceso TEXT DEFAULT '',
  hora_suceso TEXT DEFAULT '',
  numero_siniestro TEXT DEFAULT '',
  tipo_lugar_suceso TEXT DEFAULT '',
  medio_traslado TEXT DEFAULT '',
  estaba_en_puesto TEXT DEFAULT '',
  era_puesto_habitual TEXT DEFAULT '',
  forma_accidente_codigo TEXT DEFAULT '',
  forma_accidente_descripcion TEXT DEFAULT '',
  agente_causante_codigo TEXT DEFAULT '',
  agente_causante_descripcion TEXT DEFAULT '',
  agente_causante_tipo TEXT DEFAULT '',
  agente_material_codigo TEXT DEFAULT '',
  agente_material_descripcion TEXT DEFAULT '',
  naturaleza_lesion_codigo TEXT DEFAULT '',
  naturaleza_lesion_descripcion TEXT DEFAULT '',
  zona_cuerpo_codigo TEXT DEFAULT '',
  zona_cuerpo_descripcion TEXT DEFAULT '',
  inicio_ilt TEXT DEFAULT '',
  inicio_ilt_observaciones TEXT DEFAULT '',
  testigos TEXT DEFAULT '',
  descripcion_accidente TEXT DEFAULT '',
  causa_1 TEXT DEFAULT '',
  causa_2 TEXT DEFAULT '',
  causa_3 TEXT DEFAULT '',
  causa_4 TEXT DEFAULT '',
  centro_medico_primera_atencion TEXT DEFAULT '',
  denuncia_policial_numero TEXT DEFAULT '',
  comisaria TEXT DEFAULT '',
  prestador_derivado_populart TEXT DEFAULT '',
  accidente_domicilio_ocurrencia TEXT DEFAULT '',
  accidente_localidad TEXT DEFAULT '',
  responsable_apellido TEXT DEFAULT '',
  responsable_nombre TEXT DEFAULT '',
  responsable_cargo TEXT DEFAULT '',
  responsable_titulo TEXT DEFAULT '',
  responsable_mp TEXT DEFAULT '',
  responsable_firma TEXT DEFAULT '',
  recepcion_informe TEXT DEFAULT '',
  dependencia TEXT DEFAULT '',
  fecha_recepcion TEXT DEFAULT '',
  pdf_ficha_url TEXT DEFAULT '',
  doc_ficha_url TEXT DEFAULT '',
  pdf_art_url TEXT DEFAULT '',
  doc_art_url TEXT DEFAULT '',
  motivo_anulacion TEXT DEFAULT '',
  fecha_anulacion TEXT DEFAULT '',
  usuario_anulacion TEXT DEFAULT '',
  fecha_actualizacion TIMESTAMPTZ DEFAULT NOW(),
  usuario_actualizacion TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_inv_estado ON investigaciones (estado);
CREATE INDEX IF NOT EXISTS idx_inv_tipo_evento ON investigaciones (tipo_evento);
CREATE INDEX IF NOT EXISTS idx_inv_fecha_carga ON investigaciones (fecha_carga DESC);
CREATE INDEX IF NOT EXISTS idx_inv_agente_cuil ON investigaciones (agente_cuil);

-- ── Tablas hijas ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS antecedentes_at_ep (
  id TEXT PRIMARY KEY,
  id_investigacion TEXT NOT NULL,
  fecha TEXT DEFAULT '',
  dias_caidos TEXT DEFAULT '',
  observaciones TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI'
);
CREATE INDEX IF NOT EXISTS idx_ant_at_ep_inv ON antecedentes_at_ep (id_investigacion);

CREATE TABLE IF NOT EXISTS antecedentes_patologicos (
  id TEXT PRIMARY KEY,
  id_investigacion TEXT NOT NULL,
  patologia TEXT DEFAULT '',
  inicio TEXT DEFAULT '',
  observaciones TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI'
);
CREATE INDEX IF NOT EXISTS idx_ant_pat_inv ON antecedentes_patologicos (id_investigacion);

CREATE TABLE IF NOT EXISTS antecedentes_laborales (
  id TEXT PRIMARY KEY,
  id_investigacion TEXT NOT NULL,
  establecimiento TEXT DEFAULT '',
  tarea TEXT DEFAULT '',
  desde TEXT DEFAULT '',
  hasta TEXT DEFAULT '',
  observaciones TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI'
);
CREATE INDEX IF NOT EXISTS idx_ant_lab_inv ON antecedentes_laborales (id_investigacion);

CREATE TABLE IF NOT EXISTS medidas_correctivas (
  id TEXT PRIMARY KEY,
  id_investigacion TEXT NOT NULL,
  numero_causa TEXT DEFAULT '',
  medida_correctiva TEXT DEFAULT '',
  fecha TEXT DEFAULT '',
  ejecucion TEXT DEFAULT '',
  verificacion TEXT DEFAULT '',
  responsable TEXT DEFAULT '',
  estado TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI'
);
CREATE INDEX IF NOT EXISTS idx_med_cor_inv ON medidas_correctivas (id_investigacion);

CREATE TABLE IF NOT EXISTS firmas (
  id TEXT PRIMARY KEY,
  id_investigacion TEXT NOT NULL,
  tipo_firma TEXT DEFAULT '',
  nombre_firmante TEXT DEFAULT '',
  cargo TEXT DEFAULT '',
  firma_url TEXT DEFAULT '',
  fecha_firma TEXT DEFAULT '',
  activo TEXT DEFAULT 'SI'
);
CREATE INDEX IF NOT EXISTS idx_firmas_inv ON firmas (id_investigacion);

-- ── Logs ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS logs (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  usuario TEXT DEFAULT '',
  accion TEXT DEFAULT '',
  entidad TEXT DEFAULT '',
  id_entidad TEXT DEFAULT '',
  detalle TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs (timestamp DESC);

-- ── Datos por defecto ────────────────────────────────────────────────
INSERT INTO config (clave, valor, descripcion) VALUES
  ('app_name', 'SIPROSA - Investigación de Accidentes', 'Nombre visible del sistema'),
  ('template_ficha_interna_id', '', 'ID plantilla Google Docs ficha DGRHS.SOC.R03'),
  ('template_art_id', '', 'ID plantilla Google Docs formulario ART PopulArt'),
  ('carpeta_pdfs_ficha_id', '', 'ID carpeta Drive para PDF ficha interna'),
  ('carpeta_pdfs_art_id', '', 'ID carpeta Drive para PDF ART'),
  ('carpeta_docs_generados_id', '', 'ID carpeta Drive para documentos editables')
ON CONFLICT (clave) DO NOTHING;

-- ── Primer admin (ejecutar después de crear la DB) ───────────────────
-- Para crear el primer admin, conectate a la DB y ejecutá la función crearPrimerAdmin
-- desde el panel de Config dentro de la app, o ejecutá este script manualmente
-- con un hash generado. La app lo hace automáticamente desde /api con action=crearUsuario.
