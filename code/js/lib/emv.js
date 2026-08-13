/**
 * Athena · lib/emv.js
 *
 * Analizador de códigos de pago EMVCo (el estándar detrás de Yappy, Pix,
 * Nequi, UPI y prácticamente todo QR de comercio en Latinoamérica).
 *
 * La pieza clave es la etiqueta 63: un CRC-16 sobre todo el contenido.
 * Si un estafador pega una calcomanía con su propio código encima del
 * legítimo, el código nuevo tendrá su CRC correcto — pero si alguien
 * manipula un código existente sin recalcularlo, o si el impreso está
 * dañado o mal copiado, el CRC no cuadra. Verificarlo es gratis y ningún
 * lector de consumo lo hace.
 */

/** ¿La cadena tiene forma de carga EMVCo? */
export function esEMV(texto) {
  return /^0002(01|02)/.test(texto.trim()) && /63\d{2}[0-9A-F]{4}$/i.test(texto.trim());
}

/** CRC-16/CCITT-FALSE — polinomio 0x1021, inicial 0xFFFF, sin reflexión.
 *  Se calcula sobre los bytes UTF-8: los nombres de comercio con acentos o
 *  con caracteres no latinos darían un resultado distinto si se usaran
 *  unidades UTF-16. */
export function crc16(texto) {
  const bytes = typeof TextEncoder === 'function'
    ? new TextEncoder().encode(texto)
    : Buffer.from(texto, 'utf8');
  let crc = 0xFFFF;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

/** Descompone una cadena TLV en un mapa etiqueta → valor. */
export function tlv(texto) {
  const out = new Map();
  let i = 0;
  while (i + 4 <= texto.length) {
    const etiqueta = texto.slice(i, i + 2);
    const largo = parseInt(texto.slice(i + 2, i + 4), 10);
    if (!/^\d{2}$/.test(etiqueta) || Number.isNaN(largo)) return out;
    const valor = texto.slice(i + 4, i + 4 + largo);
    if (valor.length < largo) { out.set('__truncado', 'si'); return out; }
    out.set(etiqueta, valor);
    i += 4 + largo;
  }
  if (i !== texto.length) out.set('__sobrante', texto.slice(i));
  return out;
}

const MONEDAS = {
  '590': 'PAB (balboa panameño)', '840': 'USD (dólar)', '986': 'BRL (real)',
  '170': 'COP (peso colombiano)', '484': 'MXN (peso mexicano)',
  '032': 'ARS (peso argentino)', '604': 'PEN (sol)', '152': 'CLP (peso chileno)',
  '188': 'CRC (colón)', '320': 'GTQ (quetzal)', '214': 'DOP (peso dominicano)',
  '978': 'EUR (euro)', '356': 'INR (rupia)'
};

/** Moneda esperada según el país declarado en la etiqueta 58. */
const MONEDA_PAIS = {
  PA: ['590', '840'], BR: ['986'], CO: ['170'], MX: ['484'], AR: ['032'],
  PE: ['604'], CL: ['152'], CR: ['188'], GT: ['320'], DO: ['214'],
  US: ['840'], ES: ['978'], IN: ['356'], EC: ['840'], SV: ['840']
};

/** Identificadores de red dentro de las plantillas 26–51. */
const REDES = [
  [/yappy/i, 'Yappy'], [/nequi/i, 'Nequi'], [/\bpix\b|br\.gov\.bcb/i, 'Pix'],
  [/daviplata/i, 'Daviplata'], [/mercadopago|mp\.com/i, 'Mercado Pago'],
  [/upi|npci/i, 'UPI'], [/alipay/i, 'Alipay'], [/wechat/i, 'WeChat Pay'],
  [/paypal/i, 'PayPal'], [/visa/i, 'Visa'], [/mastercard|mc\.com/i, 'Mastercard'],
  [/clave|telered/i, 'Clave / Telered']
];

/**
 * Analiza una carga EMVCo.
 * @returns {{
 *   valido:boolean, crcDeclarado:string, crcCalculado:string,
 *   estatico:boolean, monto:string|null, moneda:string|null, pais:string|null,
 *   comercio:string|null, ciudad:string|null, red:string|null,
 *   referencia:string|null, urlIncrustada:string|null, anomalias:string[]
 * }}
 */
export function analizarEMV(texto) {
  const t = texto.trim();
  const anomalias = [];

  const iCRC = t.lastIndexOf('6304');
  const crcDeclarado = iCRC !== -1 ? t.slice(iCRC + 4, iCRC + 8).toUpperCase() : null;
  const crcCalculado = iCRC !== -1 ? crc16(t.slice(0, iCRC + 4)) : null;
  const valido = !!crcDeclarado && crcDeclarado === crcCalculado;

  if (iCRC === -1) anomalias.push('No incluye el campo de verificación CRC obligatorio.');
  else if (iCRC + 8 !== t.length) anomalias.push('Hay datos después del campo de verificación, que debe ir al final.');

  const campos = tlv(t);
  if (campos.has('__truncado')) anomalias.push('La estructura del código está truncada.');
  if (campos.has('__sobrante')) anomalias.push('La estructura contiene bytes que no encajan en ningún campo.');

  const iniciacion = campos.get('01');
  const estatico = iniciacion !== '12';

  const monto = campos.get('54') ?? null;
  const codMoneda = campos.get('53') ?? null;
  const pais = campos.get('58')?.toUpperCase() ?? null;
  const comercio = campos.get('59')?.trim() || null;
  const ciudad = campos.get('60')?.trim() || null;

  // Red de pago: se busca en las plantillas de cuenta de comercio (02–51).
  let red = null;
  for (const [etiqueta, valor] of campos) {
    const n = parseInt(etiqueta, 10);
    if (n >= 2 && n <= 51) {
      for (const [re, nombre] of REDES) if (re.test(valor)) { red = nombre; break; }
      if (red) break;
    }
  }

  // Datos adicionales: número de factura, referencia, propósito.
  let referencia = null;
  if (campos.has('62')) {
    const extra = tlv(campos.get('62'));
    referencia = extra.get('05') || extra.get('01') || extra.get('08') || null;
  }

  // Una URL dentro de un código de pago no tiene ningún uso legítimo.
  const url = /(https?:\/\/[^\s]+)/i.exec(t)?.[1] ?? null;

  if (monto !== null && !/^\d+(\.\d{1,2})?$/.test(monto)) {
    anomalias.push(`El monto «${monto}» no tiene formato numérico válido.`);
  }
  if (codMoneda && pais && MONEDA_PAIS[pais] && !MONEDA_PAIS[pais].includes(codMoneda)) {
    anomalias.push(`La moneda declarada no corresponde al país ${pais}.`);
  }
  if (comercio && /[<>{}\\^`|]|https?:/i.test(comercio)) {
    anomalias.push('El nombre del comercio contiene caracteres o enlaces impropios.');
  }
  if (!comercio) anomalias.push('El código no declara el nombre del comercio.');

  return {
    valido, crcDeclarado, crcCalculado, estatico, monto,
    moneda: codMoneda ? (MONEDAS[codMoneda] ?? `código ${codMoneda}`) : null,
    pais, comercio, ciudad, red, referencia, urlIncrustada: url, anomalias
  };
}