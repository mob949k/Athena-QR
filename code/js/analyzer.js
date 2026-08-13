/**
 * Athena · analyzer.js
 * Orquestador. Clasifica la carga, delega en el módulo de reglas que
 * corresponda, analiza en cascada cualquier carga anidada y puntúa.
 *
 * Sigue siendo puro: ni DOM ni red. Se puede ejecutar en Node, en un
 * service worker o en una extensión sin tocar una línea.
 *
 * Contrato:  analizar(texto) -> Informe
 */

import {
  SEVERIDAD, PESO, CATEGORIA, NOMBRE_CATEGORIA, ORDEN_CATEGORIA, ORDEN_SEVERIDAD
} from './lib/hallazgo.js';
import { reglasURL } from './reglas/url.js';
import * as carga from './reglas/carga.js';
import { esEMV } from './lib/emv.js';
import { sanear, esqueleto } from './lib/texto.js';
import { registrable } from './lib/dominio.js';
import { HOMOGLIFOS_ACTIVOS } from './lib/marcadores.js';

export { SEVERIDAD, CATEGORIA, NOMBRE_CATEGORIA, ORDEN_CATEGORIA };

/* ═════════════════════════ Veredicto ═════════════════════════ */

export const VEREDICTO = {
  SEGURO: 'seguro',
  PRECAUCION: 'precaucion',
  SOSPECHOSO: 'sospechoso',
  PELIGRO: 'peligro'
};

const UMBRAL = { precaucion: 10, sospechoso: 35, peligro: 65 };

/** Rendimientos decrecientes dentro de una misma táctica: cinco señales de
 *  ofuscación no son cinco veces peor que una, son la misma historia contada
 *  cinco veces. Entre tácticas distintas sí suman de lleno — y eso es lo que
 *  distingue un sitio descuidado de un ataque construido. */
const FACTOR = [1, 0.55, 0.3, 0.18, 0.1];

export function puntuar(hallazgos) {
  const porCategoria = new Map();
  for (const h of hallazgos) {
    if (h.severidad === SEVERIDAD.INFO) continue;
    const lista = porCategoria.get(h.categoria) ?? [];
    lista.push(PESO[h.severidad] * h.confianza);
    porCategoria.set(h.categoria, lista);
  }
  let total = 0;
  for (const pesos of porCategoria.values()) {
    pesos.sort((a, b) => b - a);
    pesos.forEach((p, i) => { total += p * (FACTOR[i] ?? 0.05); });
  }
  return Math.min(100, Math.round(total));
}

export function veredictoDe(puntaje) {
  if (puntaje >= UMBRAL.peligro) return VEREDICTO.PELIGRO;
  if (puntaje >= UMBRAL.sospechoso) return VEREDICTO.SOSPECHOSO;
  if (puntaje >= UMBRAL.precaucion) return VEREDICTO.PRECAUCION;
  return VEREDICTO.SEGURO;
}

/* ═════════════════════════ Clasificación ═════════════════════════ */

export const TIPO = {
  URL: 'url', WIFI: 'wifi', TEL: 'tel', SMS: 'sms', CORREO: 'correo',
  GEO: 'geo', CONTACTO: 'contacto', PAGO_EMV: 'pago_emv',
  PAGO_CRIPTO: 'pago_cripto', APP: 'app', EJECUTABLE: 'ejecutable', TEXTO: 'texto'
};

export const ETIQUETA_TIPO = {
  url: 'Enlace web', wifi: 'Red Wi-Fi', tel: 'Número telefónico',
  sms: 'Mensaje de texto', correo: 'Correo electrónico', geo: 'Coordenadas',
  contacto: 'Tarjeta de contacto', pago_emv: 'Cobro de comercio',
  pago_cripto: 'Pago en criptomoneda', app: 'Apertura de aplicación',
  ejecutable: 'Código ejecutable', texto: 'Texto plano'
};

const ESQUEMAS_EJECUTABLES = carga.ESQUEMAS_EJECUTABLES_SET;
const ESQUEMAS_PAGO = new Set([
  'bitcoin:', 'bitcoincash:', 'ethereum:', 'litecoin:', 'monero:', 'dogecoin:',
  'ripple:', 'solana:', 'tron:', 'upi:', 'spd:', 'pix:', 'yappy:', 'nequi:',
  'lightning:', 'lnurl:'
]);

export function clasificar(texto) {
  const t = sanear(texto).trim();
  const esquema = /^([a-z][a-z0-9+.-]*:)/i.exec(t)?.[1]?.toLowerCase() ?? null;
  const alto = t.toUpperCase();

  if (esquema && ESQUEMAS_EJECUTABLES.has(esquema)) return { tipo: TIPO.EJECUTABLE, esquema };
  if (esEMV(t)) return { tipo: TIPO.PAGO_EMV, esquema: null };
  if (alto.startsWith('WIFI:')) return { tipo: TIPO.WIFI, esquema: 'wifi:' };
  if (alto.startsWith('BEGIN:VCARD') || alto.startsWith('MECARD:') || alto.startsWith('BEGIN:VEVENT')) {
    return { tipo: TIPO.CONTACTO, esquema: null };
  }
  if (alto.startsWith('MATMSG:')) return { tipo: TIPO.CORREO, esquema: null };

  if (!esquema) {
    const cabeza = t.split(/[/?#\s]/)[0];
    if (/^[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff.-]*\.[a-z\u00a1-\uffff]{2,}$/i.test(cabeza)) {
      return { tipo: TIPO.URL, esquema: null, implicito: true };
    }
    return { tipo: TIPO.TEXTO, esquema: null };
  }
  if (esquema === 'http:' || esquema === 'https:') return { tipo: TIPO.URL, esquema };
  if (esquema === 'tel:') return { tipo: TIPO.TEL, esquema };
  if (esquema === 'sms:' || esquema === 'smsto:') return { tipo: TIPO.SMS, esquema };
  if (esquema === 'mailto:') return { tipo: TIPO.CORREO, esquema };
  if (esquema === 'geo:') return { tipo: TIPO.GEO, esquema };
  if (ESQUEMAS_PAGO.has(esquema)) return { tipo: TIPO.PAGO_CRIPTO, esquema };
  return { tipo: TIPO.APP, esquema };
}

/* ═════════════════════════ Despacho de reglas ═════════════════════════ */

function infoSimple(id, titulo, detalle) {
  return {
    id, categoria: CATEGORIA.CONTEXTO, severidad: SEVERIDAD.INFO,
    titulo, detalle, confianza: 1, tecnica: null, anidado: null
  };
}

function aplicarReglas(bruto, tipo, esquema, implicito, profundidad) {
  switch (tipo) {
    case TIPO.URL:         return reglasURL(bruto, { implicito, profundidad });
    case TIPO.EJECUTABLE:  return { url: null, ...carga.reglasEjecutable(bruto, esquema) };
    case TIPO.PAGO_EMV:    return { url: null, ...carga.reglasEMV(bruto) };
    case TIPO.PAGO_CRIPTO: return { url: null, ...carga.reglasPagoCripto(bruto, esquema) };
    case TIPO.WIFI:        return { url: null, ...carga.reglasWifi(bruto) };
    case TIPO.CONTACTO:    return { url: null, ...carga.reglasContacto(bruto) };
    case TIPO.TEL:         return { url: null, ...carga.reglasTel(bruto) };
    case TIPO.SMS:         return { url: null, ...carga.reglasSMS(bruto) };
    case TIPO.CORREO:      return { url: null, ...carga.reglasCorreo(bruto) };
    case TIPO.APP:         return { url: null, ...carga.reglasApp(bruto, esquema) };
    case TIPO.GEO:         return {
      url: null, incrustadas: [],
      hallazgos: [infoSimple('geo-info', 'Ubicación geográfica',
        'Abre un punto en tu aplicación de mapas. No ejecuta nada.')]
    };
    default:               return { url: null, ...carga.reglasTexto(bruto) };
  }
}

/* ═════════════════════════ Anotación forense ═════════════════════════ */

const RE_INVISIBLE = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]/;

/**
 * Marca cada carácter del texto original con el motivo por el que merece
 * atención. La interfaz lo convierte en resaltado.
 *
 *   dominio  el dominio registrable — lo único que decide a dónde vas
 *   homo     letra de otro alfabeto que imita a una latina
 *   noascii  carácter fuera del latino básico
 *   puny     prefijo xn-- de dominio internacionalizado
 *   arroba   símbolo que anula todo lo escrito antes
 *   cod      secuencia codificada en hexadecimal
 *   invis    carácter invisible, se sustituye por un marcador visible
 */
export function anotar(bruto, tipo = TIPO.URL, url = null) {
  const marcas = new Array(bruto.length).fill(null);
  const escruta = tipo === TIPO.URL || tipo === TIPO.EJECUTABLE || tipo === TIPO.APP;

  // 1. Resaltar el dominio registrable: responde a «¿de quién es esto?»
  if (url?.hostname) {
    const reg = registrable(url.hostname.toLowerCase());
    const i = bruto.toLowerCase().indexOf(reg);
    if (i !== -1) for (let k = i; k < i + reg.length; k++) marcas[k] = 'dominio';
  }

  // 2. Delimitar la autoridad, para juzgar el @ solo donde importa
  const iEsq = bruto.indexOf('://');
  const iniAut = iEsq === -1 ? 0 : iEsq + 3;
  let finAut = bruto.length;
  for (let k = iniAut; k < bruto.length; k++) {
    if ('/?#'.includes(bruto[k])) { finAut = k; break; }
  }

  for (let i = 0; i < bruto.length; i++) {
    const c = bruto[i];
    if (RE_INVISIBLE.test(c)) { marcas[i] = 'invis'; continue; }
    if (c === '%' && /^[0-9a-f]{2}$/i.test(bruto.slice(i + 1, i + 3))) {
      marcas[i] = marcas[i + 1] = marcas[i + 2] = 'cod';
      i += 2;
      continue;
    }
    if (c === '@' && i >= iniAut && i < finAut) { marcas[i] = 'arroba'; continue; }
    if (!escruta) continue;
    if (HOMOGLIFOS_ACTIVOS.has(c)) { marcas[i] = 'homo'; continue; }
    if (c.codePointAt(0) > 127) { marcas[i] = 'noascii'; continue; }
  }

  const iPuny = bruto.toLowerCase().indexOf('xn--');
  if (iPuny !== -1) for (let i = iPuny; i < Math.min(bruto.length, iPuny + 4); i++) marcas[i] = 'puny';

  // 3. Comprimir en tramos, haciendo visible lo invisible
  const tramos = [];
  for (let i = 0; i < bruto.length; i++) {
    const k = marcas[i];
    const t = k === 'invis' ? '◌' : bruto[i];
    const ultimo = tramos[tramos.length - 1];
    if (ultimo && ultimo.k === k) ultimo.t += t;
    else tramos.push({ t, k });
  }
  return tramos;
}

/* ═════════════════════════ Entrada principal ═════════════════════════ */

/**
 * @param {string} texto  contenido descifrado del código QR
 * @param {{profundidad?:number, vistos?:Set<string>}} [ctx]
 */
export function analizar(texto, ctx = {}) {
  const profundidad = ctx.profundidad ?? 0;
  const vistos = ctx.vistos ?? new Set();
  const bruto = String(texto ?? '');

  const { tipo, esquema, implicito } = clasificar(bruto);
  const { url = null, hallazgos, incrustadas = [] } =
    aplicarReglas(bruto, tipo, esquema, implicito, profundidad);

  // Cascada: cada carga anidada pasa por el motor completo.
  const anidados = [];
  if (profundidad < 2) {
    for (const destino of [...new Set(incrustadas)].slice(0, 3)) {
      const clave = esqueleto(destino);
      if (vistos.has(clave)) continue;
      vistos.add(clave);
      anidados.push(analizar(destino, { profundidad: profundidad + 1, vistos }));
    }
  }

  hallazgos.sort((a, b) =>
    (ORDEN_CATEGORIA.indexOf(a.categoria) - ORDEN_CATEGORIA.indexOf(b.categoria)) ||
    (ORDEN_SEVERIDAD[a.severidad] - ORDEN_SEVERIDAD[b.severidad]));

  const propio = puntuar(hallazgos);
  const peorAnidado = anidados.length ? Math.max(...anidados.map(a => a.puntaje)) : 0;
  // Un destino final peligroso contamina al enlace que lleva hasta él.
  const puntaje = Math.min(100, propio + Math.round(peorAnidado * 0.5));

  const tacticas = ORDEN_CATEGORIA
    .map(cat => ({
      categoria: cat,
      nombre: NOMBRE_CATEGORIA[cat],
      hallazgos: hallazgos.filter(h => h.categoria === cat)
    }))
    .filter(g => g.hallazgos.length);

  const criticos = hallazgos.filter(h =>
    h.severidad === SEVERIDAD.CRITICA || h.severidad === SEVERIDAD.ALTA).length;

  return {
    bruto, tipo, esquema, url,
    puntaje, propio, veredicto: veredictoDe(puntaje),
    hallazgos, tacticas, anidados, criticos,
    anotacion: anotar(bruto, tipo, url),
    profundidad
  };
}