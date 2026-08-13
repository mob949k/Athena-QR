/**
 * Athena · lib/texto.js
 * Normalización y medidas sobre cadenas. Sin DOM, sin estado.
 */

import {
  CONFUNDIBLES, SECUENCIAS, INVISIBLES, PUNTOS_ALTERNOS, BARRAS_ALTERNAS
} from '../data/confusables.js';

/** Elimina caracteres invisibles y unifica los separadores que el navegador
 *  interpreta como punto o barra. Es lo primero que debe pasarle a cualquier
 *  cadena antes de analizarla. */
export function sanear(texto) {
  return String(texto ?? '')
    .replace(INVISIBLES, '')
    .replace(PUNTOS_ALTERNOS, '.')
    .replace(BARRAS_ALTERNAS, '/');
}

/** ¿Contenía caracteres invisibles antes de sanear? */
export function tieneInvisibles(texto) {
  INVISIBLES.lastIndex = 0;
  return INVISIBLES.test(String(texto ?? ''));
}

/** ¿Contiene marcas de anulación bidireccional? (truco `xcod.exe` → `xexe.doc`) */
export function tieneBidi(texto) {
  return /[\u202A-\u202E\u2066-\u2069\u061C\u200E\u200F]/.test(String(texto ?? ''));
}

/**
 * Esqueleto de confusión (inspirado en UTS #39).
 * Reduce la cadena a la forma latina que percibe el ojo. Comparar esqueletos
 * es lo que permite detectar `раураl.com` — imposible por distancia de edición.
 */
export function esqueleto(texto) {
  let s = sanear(texto)
    .normalize('NFKD')                 // fullwidth, matemáticos, ligaduras
    .replace(/[\u0300-\u036F]/g, '');  // marcas diacríticas sueltas

  let salida = '';
  for (const c of s) salida += CONFUNDIBLES.get(c) ?? c;
  salida = salida.toLowerCase();
  for (const [re, rep] of SECUENCIAS) salida = salida.replace(re, rep);
  return salida;
}

/**
 * Normalización ligera: minúsculas y sin diacríticos, PERO sin sustituir
 * dígitos por letras. El esqueleto sí lo hace, y eso es correcto para
 * comparar marcas — pero convierte cualquier identificador hexadecimal en
 * palabras fantasma: «...b3c4...» se leería «beca».
 */
export function normalizar(texto) {
  return sanear(texto).normalize('NFKD').replace(/[\u0300-\u036F]/g, '').toLowerCase();
}

/** ¿Aparece la palabra delimitada, y no incrustada dentro de otra cadena? */
export function contienePalabra(superficie, palabra) {
  const p = normalizar(palabra).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|[^a-z0-9])${p}(?:[^a-z0-9]|$)`, 'i').test(superficie);
}

/** Distancia de Damerau-Levenshtein (incluye transposición) con corte temprano. */
export function distancia(a, b, max = 3) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const n = a.length, m = b.length;
  const d = Array.from({ length: n + 1 }, (_, i) => {
    const fila = new Array(m + 1).fill(0);
    fila[0] = i;
    return fila;
  });
  for (let j = 0; j <= m; j++) d[0][j] = j;

  for (let i = 1; i <= n; i++) {
    let minFila = Infinity;
    for (let j = 1; j <= m; j++) {
      const costo = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + costo);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
      if (d[i][j] < minFila) minFila = d[i][j];
    }
    if (minFila > max) return max + 1;
  }
  return d[n][m];
}

/** Entropía de Shannon en bits por carácter. Un dominio generado por algoritmo
 *  ronda 3.5–4.5; uno pronunciable rara vez pasa de 3.2. */
export function entropia(texto) {
  if (!texto.length) return 0;
  const f = new Map();
  for (const c of texto) f.set(c, (f.get(c) || 0) + 1);
  let h = 0;
  for (const n of f.values()) {
    const p = n / texto.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Racha consonántica más larga. Los nombres generados por algoritmo la disparan. */
export function rachaConsonantes(texto) {
  const m = texto.toLowerCase().match(/[bcdfghjklmnpqrstvwxyz]+/g);
  return m ? Math.max(...m.map(s => s.length)) : 0;
}

/** Proporción de dígitos. */
export function proporcionDigitos(texto) {
  if (!texto.length) return 0;
  return (texto.match(/\d/g) || []).length / texto.length;
}

/** Decodificación porcentual tolerante: nunca lanza excepción. */
export function desURI(texto) {
  try { return decodeURIComponent(texto); } catch { return texto; }
}

/** Decodifica recursivamente hasta que deje de cambiar (máx. 5 pasadas). */
export function desURIProfundo(texto, max = 5) {
  let previo = texto;
  for (let i = 0; i < max; i++) {
    const actual = desURI(previo);
    if (actual === previo) return { texto: actual, pasadas: i };
    previo = actual;
  }
  return { texto: previo, pasadas: max };
}

const RE_B64 = /^[A-Za-z0-9+/]{16,}={0,2}$/;
const RE_B64URL = /^[A-Za-z0-9_-]{16,}={0,2}$/;

/** Intenta interpretar una cadena como base64. Devuelve el texto o null. */
export function desBase64(texto) {
  const t = texto.trim();
  if (!RE_B64.test(t) && !RE_B64URL.test(t)) return null;
  try {
    const normal = t.replace(/-/g, '+').replace(/_/g, '/');
    const bin = typeof atob === 'function'
      ? atob(normal.padEnd(Math.ceil(normal.length / 4) * 4, '='))
      : Buffer.from(normal, 'base64').toString('binary');
    // Solo devolvemos si el resultado es texto legible: si no, era ruido binario.
    if (!/^[\x09\x0A\x0D\x20-\x7E]{8,}$/.test(bin)) return null;
    return bin;
  } catch { return null; }
}

/** Extrae la primera URL http(s) incrustada en un texto libre. */
export function urlIncrustada(texto) {
  const m = /(https?:\/\/[^\s"'<>()\[\]]{4,})/i.exec(sanear(texto));
  return m ? m[1].replace(/[.,;:!?]+$/, '') : null;
}

/** Recorta para mostrar sin romper la lectura. */
export function recortar(texto, n = 60) {
  return texto.length > n ? texto.slice(0, n) + '…' : texto;
}