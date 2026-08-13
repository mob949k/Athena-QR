/**
 * Athena · lib/dominio.js
 * Todo lo que hay que saber sobre un nombre de host.
 */

import { SUFIJOS, PLATAFORMAS, MARCAS_PLANAS, ACORTADORES } from '../data/listas.js';
import { esqueleto, distancia, entropia, rachaConsonantes, proporcionDigitos } from './texto.js';

/**
 * Dominio registrable: la parte que alguien compró.
 *   www.tienda.bancogeneral.com  →  bancogeneral.com
 *   phishing.vercel.app          →  phishing.vercel.app   (vercel.app es sufijo)
 */
export function registrable(host) {
  const p = host.toLowerCase().replace(/\.$/, '').split('.');
  if (p.length <= 2) return p.join('.');
  for (let n = 4; n >= 2; n--) {
    if (p.length >= n + 1 && SUFIJOS.has(p.slice(-n).join('.'))) return p.slice(-(n + 1)).join('.');
  }
  return p.slice(-2).join('.');
}

/** Sufijo público del host, si es una plataforma conocida. */
export function plataforma(host) {
  const p = host.toLowerCase().split('.');
  for (let n = 4; n >= 2; n--) {
    const s = p.slice(-n).join('.');
    if (PLATAFORMAS.has(s)) return { sufijo: s, descripcion: PLATAFORMAS.get(s) };
  }
  return null;
}

/** Subdominio: lo que queda a la izquierda del dominio registrable. */
export function subdominio(host) {
  const reg = registrable(host);
  return host.length > reg.length ? host.slice(0, host.length - reg.length - 1) : '';
}

/* ═══════════════ Formas de dirección IP ═══════════════
   El analizador de URL del navegador normaliza `0x7f000001`, `2130706433` y
   `0177.0.0.1` todas a `127.0.0.1`. Comparar la forma escrita con la forma
   resuelta delata la ofuscación. */

const RE_IPV4_PUNTOS = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function formaIP(hostCrudo) {
  const h = hostCrudo.toLowerCase().replace(/\.$/, '');
  if (h.startsWith('[') && h.endsWith(']')) return { tipo: 'ipv6', ofuscada: false };
  if (RE_IPV4_PUNTOS.test(h)) return { tipo: 'ipv4', ofuscada: false };
  if (/^0x[0-9a-f]+$/.test(h)) return { tipo: 'ipv4', ofuscada: true, forma: 'hexadecimal' };
  if (/^0[0-7]+$/.test(h)) return { tipo: 'ipv4', ofuscada: true, forma: 'octal' };
  if (/^\d{8,10}$/.test(h)) return { tipo: 'ipv4', ofuscada: true, forma: 'decimal entero' };
  if (/^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){1,3}$/.test(h)
      && /0x|^0\d|\.0\d/.test(h)) {
    return { tipo: 'ipv4', ofuscada: true, forma: 'mixta (octal/hexadecimal)' };
  }
  return null;
}

/** IP privada o de bucle local: apunta a la red del propio usuario. */
export function ipPrivada(ip) {
  if (!RE_IPV4_PUNTOS.test(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
}

/* ═══════════════ Coincidencia con marcas ═══════════════ */

/** Sustituciones tipográficas que un atacante realmente usa. */
const SUSTITUCIONES = {
  o: ['0', 'q'], l: ['1', 'i', 'ł'], i: ['1', 'l', 'j'], e: ['3'],
  a: ['4', '@'], s: ['5', '$', 'z'], b: ['6', '8'], g: ['9', 'q'],
  t: ['7'], m: ['rn', 'nn'], w: ['vv'], d: ['cl'], n: ['m', 'h'],
  c: ['k'], k: ['c'], u: ['v'], v: ['u'], q: ['g'], rn: ['m']
};

/** Genera variantes tipográficas plausibles de un nombre. */
export function variantes(nombre) {
  const out = new Set();
  // Sustitución de un carácter
  for (let i = 0; i < nombre.length; i++) {
    for (const r of SUSTITUCIONES[nombre[i]] || []) {
      out.add(nombre.slice(0, i) + r + nombre.slice(i + 1));
    }
  }
  // Omisión, duplicación y transposición de un carácter
  for (let i = 0; i < nombre.length; i++) {
    out.add(nombre.slice(0, i) + nombre.slice(i + 1));
    out.add(nombre.slice(0, i) + nombre[i] + nombre.slice(i));
    if (i < nombre.length - 1) {
      out.add(nombre.slice(0, i) + nombre[i + 1] + nombre[i] + nombre.slice(i + 2));
    }
  }
  // Guion insertado
  for (let i = 1; i < nombre.length; i++) out.add(nombre.slice(0, i) + '-' + nombre.slice(i));
  out.delete(nombre);
  return out;
}

const INDICE_VARIANTES = (() => {
  const m = new Map();
  for (const marca of MARCAS_PLANAS) {
    const nucleo = marca.split('.')[0];
    if (nucleo.length < 5) continue;
    for (const v of variantes(nucleo)) if (!m.has(v)) m.set(v, marca);
  }
  return m;
})();

const INDICE_ESQUELETOS = (() => {
  const m = new Map();
  for (const marca of MARCAS_PLANAS) {
    m.set(esqueleto(marca), marca);
    m.set(esqueleto(marca.split('.')[0]), marca);
  }
  return m;
})();

/**
 * Compara un dominio contra el catálogo de marcas por cuatro vías,
 * de mayor a menor certeza.
 * @returns {{marca:string, tecnica:string, confianza:number, detalle:string}|null}
 */
export function suplantacion(host) {
  const reg = registrable(host);
  const nucleo = reg.split('.')[0];
  const esqReg = esqueleto(reg);
  const esqNucleo = esqueleto(nucleo);

  if (MARCAS_PLANAS.includes(reg)) return null;      // es la marca real
  if (ACORTADORES.has(reg)) return null;             // acortador conocido, no suplanta
  if (nucleo.length < 4) return null;                // demasiado corto para juzgarlo

  // 1a. Mismo núcleo exacto, distinta extensión. Muchísimas empresas usan
  //     .com y .com.pa a la vez, así que esto NO es una imitación: es una
  //     ambigüedad que el usuario debe resolver por otra vía.
  const porNucleoExacto = MARCAS_PLANAS.find(m => esqueleto(m.split('.')[0]) === esqNucleo);
  if (porNucleoExacto && registrable(porNucleoExacto) !== reg && esqNucleo === nucleo) {
    return {
      marca: porNucleoExacto, tecnica: 'misma marca, otra extensión', confianza: .45,
      grave: false,
      detalle: `Lleva el mismo nombre que «${porNucleoExacto}» pero con otra extensión. Puede ser un sitio regional legítimo o una imitación.`
    };
  }

  // 1b. Esqueleto idéntico pero cadena distinta → homógrafo puro.
  const porEsqueleto = INDICE_ESQUELETOS.get(esqReg) || INDICE_ESQUELETOS.get(esqNucleo);
  if (porEsqueleto && porEsqueleto !== reg) {
    return {
      marca: porEsqueleto, tecnica: 'homógrafo', confianza: 1, grave: true,
      detalle: `Se lee igual que «${porEsqueleto}» pero está escrito con otros caracteres.`
    };
  }

  // 2. Variante tipográfica precalculada → typosquatting deliberado.
  const porVariante = INDICE_VARIANTES.get(esqNucleo);
  if (porVariante && registrable(porVariante) !== reg) {
    return {
      marca: porVariante, tecnica: 'typosquatting', confianza: .95, grave: true,
      detalle: `«${nucleo}» es una alteración de un carácter de «${porVariante.split('.')[0]}».`
    };
  }

  // 3. Distancia de edición corta sobre el núcleo.
  for (const marca of MARCAS_PLANAS) {
    const nm = marca.split('.')[0];
    if (nm.length < 5 || esqNucleo.length < 5) continue;
    // El margen debe ser relativo: dos ediciones sobre «bit» lo cambian entero,
    // sobre «bancogeneral» son un error de tecleo.
    const margen = Math.min(2, Math.floor(Math.min(esqNucleo.length, nm.length) / 4) + 1);
    const d = distancia(esqNucleo, esqueleto(nm), margen);
    if (d > 0 && d <= margen && Math.abs(esqNucleo.length - nm.length) <= 2) {
      return {
        marca, tecnica: 'nombre casi idéntico', confianza: .85, grave: true,
        detalle: `«${nucleo}» se diferencia de «${nm}» en ${d} carácter${d > 1 ? 'es' : ''}.`
      };
    }
  }

  // 4. Marca + palabra pegada en el mismo dominio → combosquatting.
  for (const marca of MARCAS_PLANAS) {
    const nm = marca.split('.')[0];
    if (nm.length < 5) continue;
    if (esqNucleo.includes(nm) && esqNucleo !== nm) {
      return {
        marca, tecnica: 'combosquatting', confianza: .95, grave: true,
        detalle: `El dominio contiene «${nm}» junto a otras palabras. La marca real no vende dominios así.`
      };
    }
  }
  return null;
}

/* ═══════════════ Señales de generación automática ═══════════════ */

/** Puntúa si el nombre parece generado por algoritmo (dominio desechable). */
export function pareceGenerado(host) {
  const nucleo = registrable(host).split('.')[0];
  if (nucleo.length < 8) return null;
  const h = entropia(nucleo);
  const racha = rachaConsonantes(nucleo);
  const dig = proporcionDigitos(nucleo);
  const señales = [];
  if (h > 3.6) señales.push(`entropía ${h.toFixed(1)} bits/carácter`);
  if (racha >= 5) señales.push(`${racha} consonantes seguidas`);
  if (dig > 0.3) señales.push(`${Math.round(dig * 100)} % de dígitos`);
  return señales.length >= 2 ? { señales, nucleo } : null;
}

/** Etiquetas que imitan un dominio dentro del subdominio: `google.com.evil.tk`. */
export function tldFalsoEnSubdominio(host) {
  const sub = subdominio(host);
  if (!sub) return null;
  const m = /(?:^|\.)([a-z0-9-]+)\.(com|net|org|gob|gov|edu|co|io|app|pa|mx|ar|br)$/i.exec(sub);
  return m ? `${m[1]}.${m[2]}` : null;
}