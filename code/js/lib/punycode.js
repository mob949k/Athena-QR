/**
 * Athena · lib/punycode.js
 * Decodificador RFC 3492.
 *
 * Sin esto, el ataque homógrafo se escapa por la puerta de atrás: un QR que
 * contiene `https://xn--80ak6aa92e.com` llega al analizador como ASCII
 * inocente, y la comparación de esqueletos no encuentra nada. Decodificado,
 * ese dominio se lee `аррӏе.com` — Apple escrito en cirílico.
 */

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
const SESGO_INICIAL = 72, N_INICIAL = 128, DELIMITADOR = '-';

function valorDigito(cp) {
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26;  // 0-9
  if (cp >= 0x61 && cp <= 0x7A) return cp - 0x61;       // a-z
  if (cp >= 0x41 && cp <= 0x5A) return cp - 0x41;       // A-Z
  return BASE;
}

function adaptar(delta, puntos, primera) {
  delta = primera ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / puntos);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

/** Decodifica una sola etiqueta. Devuelve la original si no es punycode o si falla. */
export function decodificarEtiqueta(etiqueta) {
  if (!/^xn--/i.test(etiqueta)) return etiqueta;
  const entrada = etiqueta.slice(4);
  const corte = entrada.lastIndexOf(DELIMITADOR);

  const salida = [];
  for (let i = 0; i < (corte < 0 ? 0 : corte); i++) {
    const cp = entrada.charCodeAt(i);
    if (cp >= 0x80) return etiqueta;   // los básicos deben ser ASCII
    salida.push(cp);
  }

  let n = N_INICIAL, i = 0, sesgo = SESGO_INICIAL;
  let idx = corte < 0 ? 0 : corte + 1;

  while (idx < entrada.length) {
    const viejoI = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= entrada.length) return etiqueta;
      const digito = valorDigito(entrada.charCodeAt(idx++));
      if (digito >= BASE) return etiqueta;
      if (digito > Math.floor((0x7FFFFFFF - i) / w)) return etiqueta;
      i += digito * w;
      const t = k <= sesgo ? TMIN : (k >= sesgo + TMAX ? TMAX : k - sesgo);
      if (digito < t) break;
      if (w > Math.floor(0x7FFFFFFF / (BASE - t))) return etiqueta;
      w *= BASE - t;
    }
    const largo = salida.length + 1;
    sesgo = adaptar(i - viejoI, largo, viejoI === 0);
    n += Math.floor(i / largo);
    if (n > 0x10FFFF) return etiqueta;
    i %= largo;
    salida.splice(i++, 0, n);
  }

  try { return String.fromCodePoint(...salida); } catch { return etiqueta; }
}

/** Decodifica un host completo, etiqueta por etiqueta. */
export function decodificarHost(host) {
  return host.split('.').map(decodificarEtiqueta).join('.');
}

/** ¿El host lleva alguna etiqueta codificada? */
export function tienePunycode(host) {
  return /(^|\.)xn--/i.test(host);
}