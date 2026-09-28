-- ════════════════════════════════════════════════════════════════════
--  SIPROSA · Migración 002 — Tabla avisos
--  Ejecutar desde Neon Dashboard → SQL Editor
-- ════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS avisos (
  id_aviso           TEXT PRIMARY KEY,
  tipo               TEXT DEFAULT 'INFORMACION',  -- ALERTA | CAPACITACION | INFORMACION
  titulo             TEXT DEFAULT '',
  cuerpo             TEXT DEFAULT '',
  activo             TEXT DEFAULT 'SI',
  fecha_publicacion  TIMESTAMPTZ DEFAULT NOW(),
  fecha_vencimiento  TEXT DEFAULT '',
  usuario_carga      TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_avisos_tipo   ON avisos (tipo);
CREATE INDEX IF NOT EXISTS idx_avisos_activo ON avisos (activo);
CREATE INDEX IF NOT EXISTS idx_avisos_fecha  ON avisos (fecha_publicacion DESC);

-- Aviso de bienvenida inicial
INSERT INTO avisos (id_aviso, tipo, titulo, cuerpo, activo, fecha_publicacion, usuario_carga)
VALUES (
  'AVI-BIENVENIDA',
  'INFORMACION',
  'SIPROSA · Investigación de Accidentes',
  'Sistema Provincial de Salud de Tucumán. Gestión y seguimiento digital de accidentes laborales, in itinere y enfermedades profesionales.',
  'SI',
  NOW(),
  'sistema'
)
ON CONFLICT (id_aviso) DO NOTHING;
