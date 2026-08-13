/**
 * Athena · lib/hallazgo.js
 * Vocabulario común de los módulos de reglas.
 */

export const SEVERIDAD = {
  INFO: 'info', BAJA: 'baja', MEDIA: 'media', ALTA: 'alta', CRITICA: 'critica'
};

export const PESO = { info: 0, baja: 6, media: 17, alta: 34, critica: 70 };

/** Táctica: qué está intentando hacer el atacante. Agrupar por táctica
 *  explica el ataque mucho mejor que una lista plana de alertas. */
export const CATEGORIA = {
  SUPLANTACION: 'suplantacion',
  OFUSCACION: 'ofuscacion',
  TRANSPORTE: 'transporte',
  INFRAESTRUCTURA: 'infraestructura',
  CARGA: 'carga',
  INGENIERIA: 'ingenieria',
  INTEGRIDAD: 'integridad',
  CONTEXTO: 'contexto'
};

export const NOMBRE_CATEGORIA = {
  suplantacion: 'Suplantación de identidad',
  ofuscacion: 'Ocultamiento del destino',
  transporte: 'Seguridad de la conexión',
  infraestructura: 'Infraestructura del sitio',
  carga: 'Contenido que se ejecuta',
  ingenieria: 'Ingeniería social',
  integridad: 'Integridad del código',
  contexto: 'Contexto'
};

/** Orden de presentación: primero lo que decide el veredicto. */
export const ORDEN_CATEGORIA = [
  'suplantacion', 'carga', 'integridad', 'ofuscacion',
  'transporte', 'infraestructura', 'ingenieria', 'contexto'
];

export const ORDEN_SEVERIDAD = { critica: 0, alta: 1, media: 2, baja: 3, info: 4 };

/**
 * @param {string} id          identificador estable, útil para pruebas
 * @param {string} categoria   táctica
 * @param {string} severidad
 * @param {string} titulo      qué pasa, en una línea
 * @param {string} detalle     por qué le importa a quien escanea
 * @param {object} [extra]     { confianza, tecnica, anidado }
 */
export function hallazgo(id, categoria, severidad, titulo, detalle, extra = {}) {
  return {
    id, categoria, severidad, titulo, detalle,
    confianza: extra.confianza ?? 1,
    tecnica: extra.tecnica ?? null,
    anidado: extra.anidado ?? null
  };
}