/**
 * Athena · reglas/carga.js
 * Reglas para todo lo que no es un enlace. Aquí vive buena parte del fraude
 * real: el QR de pago con calcomanía encima, la red Wi-Fi abierta, el enlace
 * profundo que salta a una aplicación.
 */

import { hallazgo, SEVERIDAD as S, CATEGORIA as C } from '../lib/hallazgo.js';
import { PREFIJOS_TEL_RIESGO, ESQUEMAS_EJECUTABLES } from '../data/listas.js';
import { analizarEMV } from '../lib/emv.js';
import { urlIncrustada, desURI, recortar, sanear } from '../lib/texto.js';

/* ═══════════════════════ Wi-Fi ═══════════════════════ */

export function reglasWifi(bruto) {
  const h = [], incrustadas = [];
  // El primer campo va pegado al prefijo `WIFI:`, no separado por punto y coma.
  const cuerpo = bruto.replace(/^wifi:/i, ';');
  const campo = t => new RegExp(`;${t}:((?:[^;\\\\]|\\\\.)*)`, 'i').exec(cuerpo)?.[1] ?? null;
  const ssid = campo('S');
  const tipo = (campo('T') || '').toUpperCase();
  const clave = campo('P');
  const oculta = /(?:^|;)H:true/i.test(bruto);

  h.push(hallazgo('wifi-red', C.CONTEXTO, S.INFO,
    `Red «${ssid || 'sin nombre'}»`,
    'Al aceptar, el teléfono guardará esta red y se conectará automáticamente cada vez que esté a su alcance.'));

  if (!tipo || tipo === 'NOPASS') {
    h.push(hallazgo('wifi-abierta', C.TRANSPORTE, S.ALTA,
      'Red sin contraseña',
      'En una red abierta, quien la administra ve tu tráfico y puede redirigirte a páginas falsas sin que lo notes.'));
  } else if (tipo === 'WEP') {
    h.push(hallazgo('wifi-wep', C.TRANSPORTE, S.ALTA,
      'Cifrado WEP, roto desde hace años',
      'La clave de una red WEP se descifra en minutos con herramientas públicas. Equivale a no tener contraseña.'));
  }
  if (oculta) {
    h.push(hallazgo('wifi-oculta', C.INFRAESTRUCTURA, S.MEDIA,
      'Red oculta',
      'Tu teléfono la buscará activamente en todas partes, anunciando su nombre. Eso permite rastrear el dispositivo y suplantar la red.'));
  }
  if (clave && clave.length <= 8 && tipo && tipo !== 'NOPASS') {
    h.push(hallazgo('wifi-clave-corta', C.TRANSPORTE, S.BAJA,
      'Contraseña corta',
      'Una clave de ocho caracteres o menos cede rápido ante un ataque de diccionario.'));
  }
  if (ssid && /free|gratis|gratuit|public|abierto|guest|invitado/i.test(ssid)) {
    h.push(hallazgo('wifi-cebo', C.INGENIERIA, S.MEDIA,
      'Nombre de red diseñado para atraer',
      'Los puntos de acceso falsos usan nombres genéricos y atractivos para que la gente se conecte sin preguntar de quién es la red.'));
  }
  const u = urlIncrustada(bruto);
  if (u) { incrustadas.push(u); }
  return { hallazgos: h, incrustadas };
}

/* ═══════════════════════ Pago ═══════════════════════ */

export function reglasEMV(bruto) {
  const h = [], incrustadas = [];
  const e = analizarEMV(bruto);

  h.push(hallazgo('emv-resumen', C.CONTEXTO, S.INFO,
    `Cobro${e.red ? ` por ${e.red}` : ''}${e.comercio ? ` a nombre de «${e.comercio}»` : ''}`,
    [
      e.monto ? `Monto: ${e.monto}${e.moneda ? ` ${e.moneda}` : ''}.` : 'Sin monto fijo: lo escribirás tú.',
      e.ciudad ? `Ciudad declarada: ${e.ciudad}.` : '',
      e.pais ? `País: ${e.pais}.` : '',
      e.referencia ? `Referencia: ${e.referencia}.` : ''
    ].filter(Boolean).join(' ')));

  if (e.crcDeclarado && !e.valido) {
    h.push(hallazgo('emv-crc-invalido', C.INTEGRIDAD, S.CRITICA,
      'La verificación de integridad no cuadra',
      `El código declara el sello ${e.crcDeclarado} pero su contenido produce ${e.crcCalculado}. O fue modificado después de generarse, o está mal impreso. En cualquiera de los dos casos, no lo pagues: pide al comercio que te muestre otro.`,
      { tecnica: 'manipulación del código de pago' }));
  } else if (!e.crcDeclarado) {
    h.push(hallazgo('emv-sin-crc', C.INTEGRIDAD, S.ALTA,
      'Falta el sello de verificación obligatorio',
      'Todo código de pago EMVCo debe cerrar con un CRC. Su ausencia indica que no lo generó una aplicación de pago legítima.'));
  } else {
    h.push(hallazgo('emv-crc-valido', C.CONTEXTO, S.INFO,
      'Sello de integridad correcto',
      'El contenido no fue alterado después de generarse. Esto no dice nada sobre quién lo generó: una calcomanía con el código del estafador también trae su sello correcto.'));
  }

  if (e.estatico) {
    h.push(hallazgo('emv-estatico', C.INGENIERIA, S.MEDIA,
      'Código estático: el monto lo escribes tú',
      'Los códigos estáticos son los que se imprimen y se pegan en el mostrador, y por eso son el blanco del fraude de la calcomanía. Confirma en voz alta el nombre del comercio que aparece arriba antes de confirmar el pago.'));
  }
  for (const a of e.anomalias) {
    h.push(hallazgo('emv-anomalia', C.INTEGRIDAD, S.MEDIA, 'Estructura irregular', a));
  }
  if (e.urlIncrustada) {
    incrustadas.push(e.urlIncrustada);
    h.push(hallazgo('emv-url', C.CARGA, S.ALTA,
      'El código de pago contiene un enlace',
      'Un cobro EMVCo no necesita ninguna dirección web. Su presencia indica que el código fue construido a mano.'));
  }
  return { hallazgos: h, incrustadas };
}

export function reglasPagoCripto(bruto, esquema) {
  const h = [];
  const moneda = esquema.replace(':', '');
  const cuerpo = bruto.slice(esquema.length).split('?')[0];
  const params = new URLSearchParams(bruto.split('?')[1] || '');
  const monto = params.get('amount') || params.get('value');

  h.push(hallazgo('cripto-pago', C.CARGA, S.ALTA,
    `Solicitud de pago en ${moneda}`,
    `Destino: ${recortar(cuerpo, 44)}${monto ? ` · Monto: ${monto}` : ''}. Una transferencia en criptomoneda es irreversible: no existe forma de reclamarla ni de revertirla.`));

  let formatoOk = true;
  if (moneda === 'bitcoin') {
    formatoOk = /^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/.test(cuerpo);
  } else if (moneda === 'ethereum') {
    formatoOk = /^(0x[0-9a-fA-F]{40})/.test(cuerpo.replace(/^pay-/, ''));
  }
  if (!formatoOk) {
    h.push(hallazgo('cripto-formato', C.INTEGRIDAD, S.ALTA,
      'La dirección no tiene el formato esperado',
      `No corresponde a una dirección válida de ${moneda}. Si la envías, el dinero puede perderse sin destinatario.`));
  }
  if (params.get('message') || params.get('label')) {
    const txt = `${params.get('label') || ''} ${params.get('message') || ''}`;
    if (/urgent|urgente|soporte|support|verif|premio|reembolso|refund/i.test(txt)) {
      h.push(hallazgo('cripto-cebo', C.INGENIERIA, S.ALTA,
        'Mensaje con lenguaje de presión',
        `El código incluye el texto «${recortar(txt.trim(), 60)}». Ningún cobro legítimo necesita apremiarte.`));
    }
  }
  return { hallazgos: h, incrustadas: [] };
}

/* ═══════════════════════ Contacto ═══════════════════════ */

export function reglasContacto(bruto) {
  const h = [], incrustadas = [];
  const urls = [...sanear(bruto).matchAll(/(https?:\/\/[^\s;:]+)/gi)].map(m => m[1]);

  h.push(hallazgo('contacto-info', C.CONTEXTO, S.INFO,
    'Tarjeta de contacto',
    'Guardar el contacto en sí es inofensivo. El riesgo está en lo que la tarjeta incluya dentro.'));

  if (urls.length) {
    incrustadas.push(...urls.slice(0, 3));
    h.push(hallazgo('contacto-url', C.OFUSCACION, S.MEDIA,
      `La tarjeta contiene ${urls.length === 1 ? 'un enlace' : `${urls.length} enlaces`}`,
      'Quedarán guardados en tu agenda, donde nadie los vuelve a mirar con desconfianza. Athena los analiza abajo.'));
  }
  const tel = /TEL[^:]*:([+\d\s()-]{6,})/i.exec(bruto)?.[1]?.replace(/[\s()-]/g, '');
  if (tel) {
    const riesgo = PREFIJOS_TEL_RIESGO.find(([p]) => tel.startsWith(p));
    if (riesgo) {
      h.push(hallazgo('contacto-tel-riesgo', C.INGENIERIA, S.ALTA,
        'Número de tarificación especial',
        `El prefijo corresponde a ${riesgo[1]}.`));
    }
  }
  if (/BEGIN:VEVENT/i.test(bruto)) {
    h.push(hallazgo('evento-calendario', C.CARGA, S.MEDIA,
      'Incluye un evento de calendario',
      'Se añadirá a tu agenda con su propia descripción y enlaces, y puede generar recordatorios que reaparecen más adelante.'));
  }
  return { hallazgos: h, incrustadas };
}

/* ═══════════════════════ Telefonía ═══════════════════════ */

export function reglasTel(bruto) {
  const h = [];
  const num = bruto.replace(/^tel:/i, '').replace(/[\s()-]/g, '');
  const riesgo = PREFIJOS_TEL_RIESGO.find(([p]) => num.startsWith(p));

  h.push(hallazgo('tel-info', C.CONTEXTO, S.INFO,
    `Prepara una llamada a ${num}`,
    'El teléfono abrirá el marcador con el número cargado. No llamará solo.'));

  if (riesgo) {
    h.push(hallazgo('tel-premium', C.INGENIERIA, S.CRITICA,
      'Prefijo de costo elevado',
      `El número corresponde a ${riesgo[1]}. Una llamada de un minuto puede costar varias decenas de dólares.`));
  } else if (/^\+(?!507)\d/.test(num)) {
    h.push(hallazgo('tel-internacional', C.CONTEXTO, S.BAJA,
      'Número internacional',
      'Verifica que corresponde a quien esperas antes de marcar.'));
  }
  return { hallazgos: h, incrustadas: [] };
}

export function reglasSMS(bruto) {
  const h = [];
  const cuerpo = bruto.split(/[:;]/).slice(2).join(':');
  h.push(hallazgo('sms-info', C.CARGA, S.MEDIA,
    'Prepara un mensaje de texto',
    'Enviarlo puede suscribirte a un servicio de pago, o simplemente confirmar a quien lo generó que tu número está activo, lo que multiplica el volumen de fraude que recibes.'));
  if (cuerpo && /^[A-Z]{2,8}$/.test(cuerpo.trim())) {
    h.push(hallazgo('sms-suscripcion', C.INGENIERIA, S.ALTA,
      `Mensaje precargado con la palabra «${cuerpo.trim()}»`,
      'Las palabras cortas en mayúsculas son códigos de alta a servicios de suscripción con cargo a tu línea.'));
  }
  return { hallazgos: h, incrustadas: [] };
}

/* ═══════════════════════ Aplicaciones ═══════════════════════ */

export function reglasApp(bruto, esquema) {
  const h = [], incrustadas = [];

  if (esquema === 'intent:') {
    const paquete = /package=([^;]+)/.exec(bruto)?.[1];
    const respaldo = /S\.browser_fallback_url=([^;]+)/.exec(bruto)?.[1];
    h.push(hallazgo('intent-android', C.CARGA, S.ALTA,
      'Enlace de intención de Android',
      `Intenta abrir directamente la aplicación${paquete ? ` «${paquete}»` : ''}, saltándose el navegador y cualquier aviso que este pudiera mostrarte.`));
    if (respaldo) {
      const u = desURI(respaldo);
      incrustadas.push(u);
      h.push(hallazgo('intent-respaldo', C.OFUSCACION, S.ALTA,
        'Incluye una dirección de respaldo',
        `Si la aplicación no está instalada, te llevará a «${recortar(u, 50)}». Ese es el destino que hay que examinar.`));
    }
    return { hallazgos: h, incrustadas };
  }

  h.push(hallazgo('app-externa', C.CARGA, S.MEDIA,
    `Abre una aplicación (${esquema})`,
    'Sale del navegador y entrega el control a otra aplicación, cuyo comportamiento Athena no puede inspeccionar desde aquí.'));

  const u = urlIncrustada(desURI(bruto));
  if (u) {
    incrustadas.push(u);
    h.push(hallazgo('app-url', C.OFUSCACION, S.MEDIA,
      'Contiene un enlace web',
      `Apunta a «${recortar(u, 50)}».`));
  }
  return { hallazgos: h, incrustadas };
}

export function reglasEjecutable(bruto, esquema) {
  const h = [], incrustadas = [];
  const explicacion = {
    'javascript:': 'ejecuta código dentro de la página que lo abra',
    'data:': 'incrusta un documento completo dentro del propio enlace, sin servidor que rastrear',
    'blob:': 'apunta a contenido generado en memoria por otra página',
    'file:': 'abre un archivo del propio equipo',
    'vbscript:': 'ejecuta código en el sistema',
    'ms-msdt:': 'invoca una herramienta de diagnóstico de Windows con historial de abuso para ejecutar comandos',
    'search-ms:': 'abre una búsqueda de Windows que puede apuntar a un servidor remoto'
  }[esquema] ?? 'no navega a una página: ejecuta o incrusta contenido';

  h.push(hallazgo('esquema-ejecutable', C.CARGA, S.CRITICA,
    `Esquema ${esquema} en un código QR`,
    `Este tipo de enlace ${explicacion}. Ningún cartel, factura, menú o afiche legítimo necesita esto jamás.`,
    { tecnica: 'entrega de código' }));

  if (esquema === 'data:') {
    const tipo = /^data:([^;,]+)/i.exec(bruto)?.[1];
    if (tipo && /html|svg|xml|javascript/i.test(tipo)) {
      h.push(hallazgo('data-activo', C.CARGA, S.CRITICA,
        `Documento ${tipo} incrustado`,
        'Se abrirá una página completa construida dentro del propio código QR. No existe dominio que verificar ni certificado que revisar.'));
    }
    const u = urlIncrustada(desURI(bruto));
    if (u) incrustadas.push(u);
  }
  return { hallazgos: h, incrustadas };
}

/* ═══════════════════════ Correo y texto ═══════════════════════ */

export function reglasCorreo(bruto) {
  const h = [], incrustadas = [];
  let destino = '', asunto = '', cuerpo = '';
  if (/^mailto:/i.test(bruto)) {
    const [dir, consulta] = bruto.slice(7).split('?');
    destino = desURI(dir);
    const p = new URLSearchParams(consulta || '');
    asunto = desURI(p.get('subject') || '');
    cuerpo = desURI(p.get('body') || '');
  } else {
    destino = /TO:([^;]*)/i.exec(bruto)?.[1] || '';
    asunto = /SUB:([^;]*)/i.exec(bruto)?.[1] || '';
    cuerpo = /BODY:([^;]*)/i.exec(bruto)?.[1] || '';
  }

  h.push(hallazgo('correo-info', C.CONTEXTO, S.INFO,
    `Redacta un correo a ${destino || '(sin destinatario)'}`,
    asunto ? `Asunto precargado: «${recortar(asunto, 60)}».` : 'Sin asunto precargado.'));

  if (cuerpo.length > 40) {
    h.push(hallazgo('correo-cuerpo', C.INGENIERIA, S.MEDIA,
      'El mensaje viene escrito de antemano',
      `Se enviaría en tu nombre: «${recortar(cuerpo, 90)}». Léelo entero antes de tocar enviar.`));
  }
  const u = urlIncrustada(cuerpo);
  if (u) incrustadas.push(u);
  return { hallazgos: h, incrustadas };
}

export function reglasTexto(bruto) {
  const h = [], incrustadas = [];
  const u = urlIncrustada(bruto);
  if (u) {
    incrustadas.push(u);
    h.push(hallazgo('texto-con-url', C.CONTEXTO, S.BAJA,
      'Texto con un enlace dentro',
      `El código es texto, pero contiene «${recortar(u, 50)}». Athena lo analiza abajo.`));
  } else {
    h.push(hallazgo('texto-info', C.CONTEXTO, S.INFO,
      'Texto sin acción',
      'El código no contiene ningún enlace ni instrucción. Nada se abrirá ni se ejecutará.'));
  }
  if (/\b(seed|mnemonic|frase semilla|private key|llave privada)\b/i.test(bruto)
      || /^(\w+\s){11,23}\w+$/.test(bruto.trim())) {
    h.push(hallazgo('texto-semilla', C.CARGA, S.CRITICA,
      'Parece una frase de recuperación de billetera',
      'Si alguien te pide escanear esto para «restaurar» o «verificar» una billetera, es un fraude: quien controla la frase controla los fondos. Una frase semilla legítima nunca llega en un QR ajeno.',
      { confianza: .85 }));
  }
  return { hallazgos: h, incrustadas };
}

export const ESQUEMAS_EJECUTABLES_SET = ESQUEMAS_EJECUTABLES;