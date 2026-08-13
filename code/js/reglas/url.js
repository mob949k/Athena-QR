/**
 * Athena · reglas/url.js
 * Reglas sobre enlaces. Cada bloque cubre una táctica distinta.
 */

import { hallazgo, SEVERIDAD as S, CATEGORIA as C } from '../lib/hallazgo.js';
import {
  MARCAS_PLANAS, CATEGORIA_MARCA, NOMBRE_CATEGORIA as NOM_MARCA, NUCLEOS_MARCA,
  ACORTADORES, TLD_ABUSO_ALTO, TLD_ABUSO_MEDIO, CEBOS, NOMBRE_CEBO,
  EXT_EJECUTABLE, EXT_CONTENEDOR, EXT_DOCUMENTO_MACRO,
  PARAMS_REDIRECCION, PARAMS_SENSIBLES
} from '../data/listas.js';
import {
  registrable, subdominio, plataforma, formaIP, ipPrivada,
  suplantacion, pareceGenerado, tldFalsoEnSubdominio
} from '../lib/dominio.js';
import {
  sanear, esqueleto, normalizar, contienePalabra, tieneInvisibles, tieneBidi,
  desURI, desURIProfundo, desBase64, urlIncrustada, recortar
} from '../lib/texto.js';
import { decodificarHost, tienePunycode } from '../lib/punycode.js';
import { escrituras } from '../data/confusables.js';

const RE_PORCENTAJE = /%[0-9a-f]{2}/gi;

/**
 * @param {string} bruto
 * @param {{implicito?:boolean, profundidad?:number}} opciones
 * @returns {{url:URL|null, hallazgos:Array, incrustadas:string[]}}
 */
export function reglasURL(bruto, { implicito = false, profundidad = 0 } = {}) {
  const h = [];
  const incrustadas = [];
  const limpio = sanear(bruto);

  /* ── 0. Caracteres que no deberían existir en un enlace ────────────── */

  if (tieneInvisibles(bruto)) {
    h.push(hallazgo('invisibles', C.OFUSCACION, S.CRITICA,
      'Caracteres invisibles incrustados',
      'El enlace contiene caracteres de ancho cero que no se ven en pantalla pero sí cuentan para el navegador. Su único uso es hacer que un dominio falso parezca uno real.'));
  }
  if (tieneBidi(bruto)) {
    h.push(hallazgo('bidi', C.OFUSCACION, S.CRITICA,
      'Marcas de inversión de texto',
      'El enlace usa caracteres que invierten el orden de lectura. Es la técnica con la que un archivo `.exe` se muestra como `.txt`.'));
  }
  if (limpio !== bruto.replace(/\s/g, '')) {
    const cambio = [];
    if (/[\u3002\uFF0E\uFF61\u2024]/.test(bruto)) cambio.push('puntos');
    if (/[\u2044\u2215\uFF0F]/.test(bruto)) cambio.push('barras');
    if (cambio.length) {
      h.push(hallazgo('separadores-falsos', C.OFUSCACION, S.CRITICA,
        `Separadores de ${cambio.join(' y ')} de otro alfabeto`,
        'Los navegadores los convierten en puntos o barras normales, pero a simple vista el dominio parece otro.'));
    }
  }

  /* ── 1. Análisis sintáctico ────────────────────────────────────────── */

  let url;
  try {
    url = new URL(implicito ? `https://${limpio.trim()}` : limpio.trim());
  } catch {
    h.push(hallazgo('url-invalida', C.CONTEXTO, S.MEDIA,
      'Enlace mal formado',
      'Parece un enlace pero no cumple la sintaxis de URL. Puede estar truncado, mal impreso o manipulado.'));
    return { url: null, hallazgos: h, incrustadas };
  }

  const host = url.hostname.toLowerCase();
  const reg = registrable(host);
  const sub = subdominio(host);
  const etiquetas = host.split('.');
  const tld = etiquetas[etiquetas.length - 1];
  const hostUnicode = tienePunycode(host) ? decodificarHost(host) : host;
  const ruta = desURI(url.pathname);
  const consulta = desURI(url.search);
  const esMarcaReal = MARCAS_PLANAS.includes(reg);

  if (implicito) {
    h.push(hallazgo('esquema-omitido', C.CONTEXTO, S.BAJA,
      'Enlace sin protocolo',
      'El código no indica http ni https. Athena asumió https para poder analizarlo; el destino real puede diferir.'));
  }

  /* ── 2. Host escrito frente a host real ────────────────────────────── */

  const crudoAutoridad = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(limpio)?.[1] ?? '';
  const crudoHost = crudoAutoridad.replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase();
  const ip = formaIP(crudoHost);

  if (ip?.ofuscada) {
    h.push(hallazgo('ip-ofuscada', C.OFUSCACION, S.CRITICA,
      `Dirección IP escrita en ${ip.forma}`,
      `Se muestra como «${crudoHost}» pero el navegador la resuelve a ${host}. Escribir una IP en otra base solo sirve para que no la reconozcas.`));
  } else if (crudoHost && crudoHost !== host && crudoHost !== hostUnicode
             && !tienePunycode(host) && crudoHost.replace(/\.$/, '') !== host) {
    h.push(hallazgo('host-reescrito', C.OFUSCACION, S.ALTA,
      'El host escrito no es el host real',
      `El texto dice «${recortar(crudoHost, 40)}» pero el navegador irá a «${host}».`));
  }

  /* ── 3. Transporte ─────────────────────────────────────────────────── */

  if (url.protocol === 'http:') {
    h.push(hallazgo('sin-tls', C.TRANSPORTE, S.ALTA,
      'Conexión sin cifrar (HTTP)',
      'Cualquiera en la misma red puede leer o alterar lo que envíes, incluidas contraseñas. Hoy no existe motivo legítimo para que un sitio público use HTTP.'));
  }
  if (url.port && url.port !== '80' && url.port !== '443') {
    h.push(hallazgo('puerto-inusual', C.INFRAESTRUCTURA, S.MEDIA,
      `Puerto no estándar (${url.port})`,
      'El tráfico web público casi nunca usa puertos distintos de 80 o 443. Suele indicar un servicio improvisado.'));
  }

  /* ── 4. Autoridad ──────────────────────────────────────────────────── */

  if (url.username || url.password) {
    h.push(hallazgo('credenciales-url', C.SUPLANTACION, S.CRITICA,
      'Nombre falso antes del símbolo @',
      `Todo lo escrito antes del @ es decorado: el navegador solo obedece lo que va después. El destino real es «${host}».`,
      { tecnica: 'suplantación por userinfo' }));
  }
  if (ip) {
    const priv = ipPrivada(host);
    h.push(hallazgo('host-ip', C.INFRAESTRUCTURA, priv ? S.MEDIA : S.ALTA,
      priv ? 'Dirección de red local' : 'Dirección IP en vez de dominio',
      priv
        ? 'Apunta a un equipo dentro de tu propia red, no a un sitio público. Fuera de esa red el enlace no funcionará.'
        : 'Los servicios legítimos usan nombres de dominio con certificado. Una IP desnuda suele indicar infraestructura desechable.'));
  }
  if (!host.includes('.') && !ip) {
    h.push(hallazgo('host-sin-punto', C.INFRAESTRUCTURA, S.MEDIA,
      'Nombre de host sin dominio',
      'Apunta a un equipo de la red local. Un sitio público siempre tiene al menos un punto en su nombre.'));
  }
  const nSub = sub ? sub.split('.').length : 0;
  if (nSub >= 3) {
    h.push(hallazgo('subdominios', C.OFUSCACION, S.MEDIA,
      `Cadena de ${nSub} subdominios antes del dominio real`,
      'Las cadenas largas empujan el dominio real fuera de la vista en la barra de direcciones del teléfono, que es donde se decide si un enlace es de fiar.'));
  }
  const tldFalso = tldFalsoEnSubdominio(host);
  if (tldFalso && !esMarcaReal) {
    h.push(hallazgo('tld-en-subdominio', C.SUPLANTACION, S.ALTA,
      `«${tldFalso}» aparece como subdominio, no como dominio`,
      `Se lee como si fuera el sitio de ${tldFalso}, pero el dueño del enlace es «${reg}». Lo que manda es siempre lo que está justo antes de la primera barra.`,
      { tecnica: 'dominio decorativo' }));
  }
  if ((reg.split('.')[0].match(/-/g) || []).length >= 3) {
    h.push(hallazgo('guiones', C.SUPLANTACION, S.MEDIA,
      'Dominio con muchos guiones',
      'Los dominios corporativos rara vez encadenan tres o más guiones. Es un patrón típico de dominios creados para una sola campaña.'));
  }

  /* ── 5. Internacionalización y homógrafos ──────────────────────────── */

  if (tienePunycode(host)) {
    h.push(hallazgo('punycode', C.SUPLANTACION, S.ALTA,
      'Dominio con caracteres no latinos',
      `Escrito como «${host}», se muestra en pantalla como «${hostUnicode}».`,
      { tecnica: 'dominio internacionalizado' }));
  }
  for (const etiqueta of hostUnicode.split('.')) {
    const scr = escrituras(etiqueta);
    if (scr.length > 1) {
      h.push(hallazgo('mezcla-escrituras', C.SUPLANTACION, S.CRITICA,
        `Mezcla de alfabetos en «${etiqueta}»`,
        `Combina ${scr.join(' y ')} dentro de una misma palabra. Ningún dominio legítimo lo hace: es la firma del ataque homógrafo.`,
        { tecnica: 'homógrafo de escritura mixta' }));
      break;
    }
  }

  /* ── 6. Suplantación de marca ──────────────────────────────────────── */

  if (esMarcaReal) {
    const cat = CATEGORIA_MARCA.get(reg);
    h.push(hallazgo('marca-exacta', C.CONTEXTO, S.INFO,
      `Dominio oficial de ${NOM_MARCA[cat] ?? 'una marca conocida'}`,
      `«${reg}» coincide exactamente con el dominio de una marca del catálogo. Descarta la suplantación por nombre parecido, pero no garantiza que la página concreta sea legítima.`));
  } else {
    const sup = suplantacion(hostUnicode) || suplantacion(host);
    if (sup?.grave) {
      h.push(hallazgo('suplantacion-marca', C.SUPLANTACION, S.CRITICA,
        `Imita a ${sup.marca}`,
        `${sup.detalle} Si esperabas entrar a ${sup.marca}, este no es su sitio.`,
        { tecnica: sup.tecnica, confianza: sup.confianza }));
    } else if (sup) {
      h.push(hallazgo('marca-otra-extension', C.SUPLANTACION, S.MEDIA,
        `Mismo nombre que ${sup.marca}, distinta extensión`,
        `${sup.detalle} Confírmalo por un canal que ya conozcas antes de introducir datos.`,
        { tecnica: sup.tecnica, confianza: sup.confianza }));
    }

    const esqSub = esqueleto(sub + ' ' + ruta);
    for (const nucleo of NUCLEOS_MARCA) {
      if (nucleo.length < 5) continue;
      if (esqSub.includes(nucleo) && !esqueleto(reg).includes(nucleo)) {
        h.push(hallazgo('marca-fuera-del-dominio', C.SUPLANTACION, S.CRITICA,
          `«${nucleo}» aparece, pero no es el dueño del enlace`,
          `El nombre de la marca está en el subdominio o en la ruta, donde cualquiera puede escribir lo que quiera. El dominio registrado es «${reg}».`,
          { tecnica: 'marca decorativa' }));
        break;
      }
    }
  }

  /* ── 7. Infraestructura ────────────────────────────────────────────── */

  if (ACORTADORES.has(reg)) {
    h.push(hallazgo('acortador', C.OFUSCACION, S.MEDIA,
      'Enlace acortado',
      'El destino real está oculto tras un redireccionamiento. Ningún análisis del texto puede verificarlo, y quien lo creó puede cambiar el destino después de que lo compartas.'));
  }
  const plat = plataforma(host);
  if (plat && !esMarcaReal) {
    const efimera = /ngrok|trycloudflare|loca\.lt|serveo|duckdns|no-ip|hopto|ddns/.test(plat.sufijo);
    // Un formulario o documento de un proveedor mayor es cotidiano; un sitio
    // web arbitrario en alojamiento gratuito, mucho menos.
    const documental = /forms\.gle|sites\.google|typeform|jotform|notion\.site|canva\.site/.test(plat.sufijo);
    h.push(hallazgo('plataforma-gratuita', C.INFRAESTRUCTURA,
      efimera ? S.ALTA : documental ? S.BAJA : S.MEDIA,
      `Alojado en ${plat.sufijo}`,
      documental
        ? `Es ${plat.descripcion}. Su uso es cotidiano, pero recuerda que cualquiera puede crear uno y pedir datos en él: ninguna entidad seria te pedirá contraseñas ahí.`
        : `Es ${plat.descripcion}. Se obtiene en minutos, sin verificación de identidad y sin costo. Un banco o una entidad pública nunca publica ahí.`));
  }
  if (TLD_ABUSO_ALTO.has(tld)) {
    h.push(hallazgo('tld-abuso-alto', C.INFRAESTRUCTURA, S.ALTA,
      `Extensión .${tld}`,
      tld === 'zip' || tld === 'mov'
        ? `La extensión .${tld} coincide con un formato de archivo, lo que permite disfrazar un enlace de descarga.`
        : `Registro gratuito o casi gratuito, sin verificación. Concentra una proporción desmedida de campañas de fraude.`));
  } else if (TLD_ABUSO_MEDIO.has(tld)) {
    h.push(hallazgo('tld-abuso-medio', C.INFRAESTRUCTURA, S.MEDIA,
      `Extensión .${tld} de bajo costo`,
      'Es barata y de registro inmediato, lo que la hace frecuente en dominios de un solo uso.'));
  }
  const gen = pareceGenerado(host);
  if (gen && !esMarcaReal && !plat) {
    h.push(hallazgo('nombre-generado', C.INFRAESTRUCTURA, S.MEDIA,
      'El nombre parece generado por un algoritmo',
      `«${gen.nucleo}» presenta ${gen.señales.join(' y ')}. Es el patrón de los dominios creados en masa y descartados en días.`));
  }

  /* ── 8. Ruta y parámetros ──────────────────────────────────────────── */

  const archivo = ruta.split('/').pop() || '';
  const partes = archivo.toLowerCase().split('.');
  const ext = partes.length > 1 ? partes.pop() : '';

  if (EXT_EJECUTABLE.has(ext)) {
    h.push(hallazgo('descarga-ejecutable', C.CARGA, S.CRITICA,
      `Descarga directa de un archivo .${ext}`,
      'El enlace no lleva a una página sino a un programa que se ejecutará en tu equipo. Un QR nunca es una vía legítima para instalar software.'));
  } else if (EXT_DOCUMENTO_MACRO.has(ext)) {
    h.push(hallazgo('documento-macro', C.CARGA, S.ALTA,
      `Documento con macros (.${ext})`,
      'Este formato puede ejecutar código al abrirse. Se usa para entregar programas maliciosos disfrazados de factura o formulario.'));
  } else if (EXT_CONTENEDOR.has(ext)) {
    h.push(hallazgo('descarga-contenedor', C.CARGA, S.MEDIA,
      `Descarga de un archivo comprimido (.${ext})`,
      'Los comprimidos se usan para que el contenido real no pueda inspeccionarse antes de descargarlo.'));
  }
  if (partes.length >= 2) {
    const penultima = partes[partes.length - 1];
    if (['pdf', 'doc', 'docx', 'jpg', 'png', 'xls', 'xlsx', 'txt'].includes(penultima)
        && (EXT_EJECUTABLE.has(ext) || EXT_CONTENEDOR.has(ext))) {
      h.push(hallazgo('doble-extension', C.OFUSCACION, S.CRITICA,
        `Doble extensión: .${penultima}.${ext}`,
        `El archivo aparenta ser un ${penultima.toUpperCase()} pero es un .${ext}. El disfraz es deliberado.`));
    }
  }
  // Se evalúa sobre la URL completamente descodificada: el salto suele venir
  // codificado dos veces justamente para que una comprobación ingenua lo pierda.
  const planaCompleta = desURIProfundo(limpio).texto;
  if (/(?:^|[^\w.])\.\.[/\\]/.test(planaCompleta) || /%2e%2e/i.test(planaCompleta)) {
    h.push(hallazgo('traversal', C.CARGA, S.ALTA,
      'Secuencia de salto de directorio',
      'La ruta intenta subir por encima de la carpeta pública del servidor. Es un patrón de ataque, no de navegación normal.'));
  }
  if (/%00|\x00/.test(limpio)) {
    h.push(hallazgo('byte-nulo', C.OFUSCACION, S.ALTA,
      'Byte nulo en el enlace',
      'Se usa para truncar la lectura del destino en programas que no lo esperan.'));
  }

  const params = [...url.searchParams.keys()].map(k => k.toLowerCase());
  const sensibles = params.filter(k => PARAMS_SENSIBLES.includes(k));
  if (sensibles.length) {
    h.push(hallazgo('param-sensible', C.CARGA, S.ALTA,
      `El enlace lleva datos sensibles a la vista (${sensibles.join(', ')})`,
      'Estos valores quedan registrados en el historial, en los registros del servidor y en cualquier equipo intermedio. Un sitio legítimo no los pone en la dirección.'));
  }

  /* ── 9. Codificación ───────────────────────────────────────────────── */

  const nCod = (limpio.match(RE_PORCENTAJE) || []).length;
  const { pasadas } = desURIProfundo(limpio);
  if (pasadas >= 2 || /%25[0-9a-f]{2}/i.test(limpio)) {
    h.push(hallazgo('doble-codificacion', C.OFUSCACION, S.ALTA,
      'Codificación aplicada varias veces',
      'El enlace codifica el propio símbolo de codificación. Sirve para atravesar filtros de seguridad que solo descifran una vez.'));
  } else if (nCod >= 6) {
    h.push(hallazgo('codificacion-excesiva', C.OFUSCACION, S.MEDIA,
      `${nCod} caracteres codificados`,
      'La codificación porcentual masiva oculta palabras y rutas al ojo humano sin cambiar nada para el navegador.'));
  }
  if (/%(2f|3a|40|2e|5c)/i.test(url.search + url.pathname)) {
    h.push(hallazgo('estructura-codificada', C.OFUSCACION, S.MEDIA,
      'Símbolos de estructura codificados',
      'Se han codificado barras, dos puntos o arrobas, que son justamente los caracteres que definen a dónde va el enlace.'));
  }

  /* ── 10. Ingeniería social ─────────────────────────────────────────── */

  const superficie = normalizar(`${sub} ${reg.split('.')[0]} ${ruta} ${consulta}`);
  const tacticas = [];
  for (const [grupo, palabras] of Object.entries(CEBOS)) {
    if (palabras.some(p => contienePalabra(superficie, p))) tacticas.push(grupo);
  }
  if (tacticas.length && !esMarcaReal) {
    const sev = tacticas.length >= 2 ? S.ALTA : S.MEDIA;
    h.push(hallazgo('cebo', C.INGENIERIA, sev,
      `Vocabulario de ${tacticas.map(t => NOMBRE_CEBO[t]).join(' y ')}`,
      'El enlace usa palabras diseñadas para provocar una reacción rápida. Combinado con un dominio que no es el oficial, es el patrón estándar del fraude.',
      { confianza: tacticas.length >= 2 ? 1 : .8 }));
  }

  /* ── 11. Volumen ───────────────────────────────────────────────────── */

  if (limpio.length > 250) {
    h.push(hallazgo('longitud-extrema', C.OFUSCACION, S.MEDIA,
      `Enlace de ${limpio.length} caracteres`,
      'A esta longitud es imposible revisarlo a simple vista, que es precisamente el objetivo.'));
  } else if (limpio.length > 120) {
    h.push(hallazgo('longitud-alta', C.CONTEXTO, S.BAJA,
      `Enlace de ${limpio.length} caracteres`,
      'Más largo de lo habitual. Revisa el dominio con calma antes de abrir.'));
  }

  /* ── 12. Cargas anidadas ───────────────────────────────────────────── */

  if (profundidad < 2) {
    for (const [clave, valor] of url.searchParams) {
      if (valor.length < 8) continue;
      const k = clave.toLowerCase();

      if (PARAMS_REDIRECCION.includes(k)) {
        const destino = urlIncrustada(desURI(valor)) || (/^https?:\/\//i.test(desURI(valor)) ? desURI(valor) : null);
        if (destino) {
          incrustadas.push(destino);
          h.push(hallazgo('redireccion-param', C.OFUSCACION, S.ALTA,
            `El parámetro «${clave}» contiene otro enlace`,
            `Tras abrirse, el sitio te enviará a «${recortar(destino, 50)}». Ese destino es el que realmente importa.`));
        }
      }

      const b64 = desBase64(valor);
      if (b64) {
        const destino = urlIncrustada(b64);
        if (destino) {
          incrustadas.push(destino);
          h.push(hallazgo('base64-param', C.OFUSCACION, S.ALTA,
            `El parámetro «${clave}» esconde un enlace en base64`,
            `Descodificado apunta a «${recortar(destino, 50)}». Codificar el destino solo sirve para que no lo leas.`));
        } else if (/https?|www\.|\.(com|net|tk|xyz)/i.test(b64)) {
          h.push(hallazgo('base64-sospechoso', C.OFUSCACION, S.MEDIA,
            `El parámetro «${clave}» contiene texto codificado`,
            `Descodificado dice «${recortar(b64, 50)}».`));
        }
      }
    }

    const enFragmento = urlIncrustada(desURI(url.hash));
    if (enFragmento) {
      incrustadas.push(enFragmento);
      h.push(hallazgo('url-en-fragmento', C.OFUSCACION, S.ALTA,
        'Hay otro enlace después del símbolo #',
        `Esa parte no llega al servidor: la usa un guion en la propia página para redirigirte a «${recortar(enFragmento, 50)}» sin dejar rastro en los registros.`));
    }
  }

  return { url, hallazgos: h, incrustadas };
}