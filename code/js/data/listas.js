/**
 * Athena · data/listas.js
 * Todo el conocimiento del dominio vive aquí, separado de la lógica.
 * Actualizar una lista no debe obligar a tocar una sola regla.
 */

/* ══════════════════ Marcas suplantadas ══════════════════
   Se prioriza aquello por lo que un atacante cobra: banca, pago, identidad,
   paquetería y trámite público. Con foco en Panamá y Latinoamérica, que es
   donde ningún escáner internacional cubre bien. */

export const MARCAS = {
  banca_pa: [
    'bancogeneral.com', 'banistmo.com', 'baccredomatic.com', 'globalbank.com.pa',
    'banconacional.com.pa', 'bancopacifico.com', 'multibank.com.pa',
    'stbanco.com', 'capitalbank.com.pa', 'banvivienda.com', 'bicsa.com',
    'yappy.com.pa', 'clave.com.pa', 'telered.com.pa'
  ],
  banca_latam: [
    'bancolombia.com', 'davivienda.com', 'bbva.com', 'santander.com',
    'bancochile.cl', 'itau.com.br', 'bradesco.com.br', 'nubank.com.br',
    'banorte.com', 'bancomer.com', 'banamex.com', 'scotiabank.com',
    'mercadopago.com', 'mercadolibre.com', 'pagofacil.com', 'nequi.com.co'
  ],
  pago_global: [
    'paypal.com', 'stripe.com', 'wise.com', 'westernunion.com',
    'moneygram.com', 'remitly.com', 'zellepay.com', 'venmo.com',
    'binance.com', 'coinbase.com', 'kraken.com', 'metamask.io',
    'ledger.com', 'trezor.io', 'blockchain.com', 'bybit.com', 'okx.com'
  ],
  identidad: [
    'google.com', 'gmail.com', 'accounts.google.com', 'microsoft.com',
    'office.com', 'office365.com', 'outlook.com', 'live.com', 'apple.com',
    'icloud.com', 'appleid.apple.com', 'amazon.com', 'facebook.com',
    'instagram.com', 'whatsapp.com', 'x.com', 'twitter.com', 'linkedin.com',
    'tiktok.com', 'telegram.org', 'discord.com', 'steamcommunity.com',
    'netflix.com', 'spotify.com', 'dropbox.com', 'adobe.com', 'github.com'
  ],
  gobierno_pa: [
    'dgi.mef.gob.pa', 'mef.gob.pa', 'ente.gob.pa', 'ansi.gob.pa',
    'meduca.gob.pa', 'minsa.gob.pa', 'css.gob.pa', 'tribunal-electoral.gob.pa',
    'migracion.gob.pa', 'atp.gob.pa', 'municipio.gob.pa', 'panamatramita.gob.pa'
  ],
  servicios_pa: [
    'copaair.com', 'claro.com.pa', 'tigo.com.pa', 'masmovil.com.pa',
    'cableonda.com', 'naturgy.com.pa', 'idaan.gob.pa', 'ensa.com.pa',
    'correosdepanama.gob.pa', 'panapass.com.pa'
  ],
  paqueteria: [
    'dhl.com', 'fedex.com', 'ups.com', 'usps.com', 'correos.es',
    'aeropost.com', 'airbox.com.pa', 'mailboxespanama.com'
  ]
};

/** Vista plana para los bucles de comparación. */
export const MARCAS_PLANAS = Object.values(MARCAS).flat();

/** Índice inverso: dominio → categoría, para explicar el hallazgo. */
export const CATEGORIA_MARCA = (() => {
  const m = new Map();
  for (const [cat, lista] of Object.entries(MARCAS)) for (const d of lista) m.set(d, cat);
  return m;
})();

export const NOMBRE_CATEGORIA = {
  banca_pa: 'banca panameña', banca_latam: 'banca latinoamericana',
  pago_global: 'pagos y criptomonedas', identidad: 'cuenta personal',
  gobierno_pa: 'entidad pública panameña', servicios_pa: 'servicio panameño',
  paqueteria: 'paquetería'
};

/** Núcleos de marca para buscar dentro de subdominios y rutas. */
export const NUCLEOS_MARCA = (() => {
  const s = new Set();
  for (const d of MARCAS_PLANAS) {
    const nucleo = d.split('.')[0];
    if (nucleo.length >= 5 && nucleo !== 'accounts' && nucleo !== 'appleid') s.add(nucleo);
  }
  ['paypal', 'yappy', 'banistmo', 'zelle', 'binance', 'netflix', 'whatsapp',
   'facebook', 'instagram', 'microsoft', 'outlook', 'icloud', 'appleid',
   'mercadopago', 'nequi', 'bancogeneral', 'panapass', 'meduca'].forEach(n => s.add(n));
  return [...s];
})();

/* ══════════════════ Sufijos públicos ══════════════════
   Subconjunto de la Public Suffix List. Incluye a propósito las plataformas
   de alojamiento gratuito: tratarlas como sufijo público hace que
   `banco-falso.vercel.app` se resuelva como dominio registrable completo,
   que es exactamente lo que hay que evaluar. */

export const SUFIJOS = new Set([
  // ccTLD de segundo nivel
  'com.pa', 'net.pa', 'org.pa', 'gob.pa', 'edu.pa', 'ac.pa', 'sld.pa', 'abo.pa',
  'com.ar', 'gob.ar', 'edu.ar', 'com.br', 'gov.br', 'org.br', 'com.mx',
  'gob.mx', 'edu.mx', 'com.co', 'gov.co', 'edu.co', 'com.pe', 'gob.pe',
  'com.ve', 'com.ec', 'gob.ec', 'com.uy', 'com.py', 'com.bo', 'com.do',
  'com.gt', 'com.sv', 'com.hn', 'com.ni', 'com.cr', 'go.cr', 'ac.cr',
  'com.cu', 'com.pr', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
  'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'com.au', 'net.au', 'org.au',
  'gov.au', 'edu.au', 'co.nz', 'com.tr', 'com.cn', 'net.cn', 'org.cn',
  'gov.cn', 'com.hk', 'com.tw', 'com.sg', 'com.my', 'com.ph', 'co.id',
  'co.th', 'co.in', 'net.in', 'org.in', 'com.es', 'gob.es', 'com.pt',
  'co.za', 'com.ng', 'com.eg', 'com.sa', 'com.ua', 'com.ru', 'org.il',
  'co.il', 'com.vn', 'com.pk', 'com.bd',

  // Alojamiento gratuito / efímero
  'vercel.app', 'netlify.app', 'netlify.com', 'pages.dev', 'workers.dev',
  'r2.dev', 'web.app', 'firebaseapp.com', 'github.io', 'gitlab.io',
  'glitch.me', 'repl.co', 'replit.app', 'render.com', 'onrender.com',
  'herokuapp.com', 'fly.dev', 'railway.app', 'surge.sh', 'now.sh',
  '000webhostapp.com', 'infinityfreeapp.com', 'byethost.com', 'rf.gd',
  'wixsite.com', 'weebly.com', 'squarespace.com', 'blogspot.com',
  'wordpress.com', 'webflow.io', 'framer.app', 'carrd.co', 'notion.site',
  'my.canva.site', 'godaddysites.com', 'strikinglydns.com', 'mystrikingly.com',
  'sites.google.com', 'forms.gle', 'typeform.com', 'jotform.com',
  'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt',
  'serveo.net', 'localto.net', 'telebit.io', 'duckdns.org', 'no-ip.org',
  'hopto.org', 'ddns.net', 'zapto.org', 'sytes.net', 'freedns.org',
  'ipfs.io', 'ipfs.dweb.link', 'azurewebsites.net', 'cloudfront.net',
  's3.amazonaws.com', 'blob.core.windows.net', 'storage.googleapis.com',
  'appspot.com', 'discordapp.net', 'cdn.discordapp.com'
]);

/** Plataformas cuya presencia justifica una advertencia y su explicación. */
export const PLATAFORMAS = new Map(Object.entries({
  'vercel.app': 'despliegue instantáneo y gratuito',
  'netlify.app': 'despliegue instantáneo y gratuito',
  'pages.dev': 'despliegue instantáneo y gratuito',
  'workers.dev': 'función serverless gratuita',
  'web.app': 'alojamiento gratuito de Firebase',
  'firebaseapp.com': 'alojamiento gratuito de Firebase',
  'github.io': 'páginas estáticas gratuitas',
  'glitch.me': 'entorno de pruebas gratuito',
  'repl.co': 'entorno de pruebas gratuito',
  'replit.app': 'entorno de pruebas gratuito',
  'herokuapp.com': 'alojamiento gratuito',
  '000webhostapp.com': 'alojamiento gratuito sin verificación',
  'infinityfreeapp.com': 'alojamiento gratuito sin verificación',
  'rf.gd': 'alojamiento gratuito sin verificación',
  'wixsite.com': 'constructor de sitios sin dominio propio',
  'weebly.com': 'constructor de sitios sin dominio propio',
  'blogspot.com': 'blog gratuito',
  'carrd.co': 'página de una sola sección',
  'notion.site': 'página de Notion publicada',
  'sites.google.com': 'sitio de Google publicado',
  'forms.gle': 'formulario de Google',
  'jotform.com': 'formulario alojado por terceros',
  'typeform.com': 'formulario alojado por terceros',
  'ngrok.io': 'túnel temporal a un equipo personal',
  'ngrok-free.app': 'túnel temporal a un equipo personal',
  'trycloudflare.com': 'túnel temporal a un equipo personal',
  'loca.lt': 'túnel temporal a un equipo personal',
  'serveo.net': 'túnel temporal a un equipo personal',
  'duckdns.org': 'DNS dinámico apuntando a una conexión doméstica',
  'no-ip.org': 'DNS dinámico apuntando a una conexión doméstica',
  'hopto.org': 'DNS dinámico apuntando a una conexión doméstica',
  'ddns.net': 'DNS dinámico apuntando a una conexión doméstica',
  'cdn.discordapp.com': 'archivo subido a Discord',
  's3.amazonaws.com': 'depósito de archivos sin dominio propio',
  'blob.core.windows.net': 'depósito de archivos sin dominio propio',
  'storage.googleapis.com': 'depósito de archivos sin dominio propio'
}));

/* ══════════════════ Acortadores ══════════════════ */

export const ACORTADORES = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd',
  'ow.ly', 'buff.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly',
  'bl.ink', 's.id', 'lnkd.in', 'tiny.cc', 'shrtco.de', 'qr.ae', 'urlz.fr',
  'acortar.link', 'n9.cl', 'urlis.net', 'chilp.it', 'clck.ru', 'vk.cc',
  'trib.al', 'dlvr.it', 'ift.tt', 'lnk.to', 'linktr.ee', 'shorturl.com',
  'soo.gd', 'tny.im', 'gg.gg', 'shrinkme.io', 'adf.ly', 'ouo.io',
  'exe.io', 'shrinke.me', 'za.gl', 'mgnet.me', 'short.gy', 'kutt.it',
  't.ly', 'shorte.st', 'fc.lc', 'cutzy.com', 'urlshortner.io'
]);

/* ══════════════════ Extensiones de dominio ══════════════════
   Dos niveles: abuso masivo documentado vs. abuso elevado. */

export const TLD_ABUSO_ALTO = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq',              // registro gratuito
  'zip', 'mov',                              // colisionan con nombres de archivo
  'top', 'xyz', 'cyou', 'sbs', 'cfd', 'lol',
  'rest', 'quest', 'bond', 'beauty', 'hair', 'skin', 'makeup', 'mom'
]);

export const TLD_ABUSO_MEDIO = new Set([
  'click', 'link', 'live', 'life', 'online', 'site', 'website', 'space',
  'store', 'shop', 'fun', 'icu', 'buzz', 'monster', 'work', 'world',
  'today', 'club', 'vip', 'best', 'win', 'bid', 'loan', 'download',
  'stream', 'racing', 'review', 'party', 'date', 'trade', 'science',
  'accountant', 'faith', 'cricket', 'gdn', 'men', 'kim', 'country', 'wang',
  'autos', 'boats', 'motorcycles', 'yachts', 'homes', 'digital', 'cloud'
]);

/* ══════════════════ Vocabulario de engaño ══════════════════ */

export const CEBOS = {
  credencial: [
    'login', 'log-in', 'signin', 'sign-in', 'acceso', 'ingresar', 'ingreso',
    'entrar', 'autenticar', 'auth', 'session', 'sesion', 'password',
    'contrasena', 'contraseña', 'clave', 'pin', 'otp', 'token', '2fa', 'mfa',
    'credencial', 'usuario', 'account', 'cuenta', 'portal', 'webmail'
  ],
  urgencia: [
    'verify', 'verificar', 'verificacion', 'verificación', 'confirmar',
    'confirm', 'validar', 'validacion', 'update', 'actualizar', 'actualice',
    'suspend', 'suspendido', 'suspension', 'bloqueado', 'bloqueo', 'restringido',
    'urgente', 'inmediato', 'expira', 'vencido', 'caducado', 'ultimo-aviso',
    'reactivar', 'restaurar', 'recuperar', 'recovery', 'unlock', 'desbloquear',
    'alerta', 'aviso', 'importante', 'accion-requerida'
  ],
  cebo: [
    'premio', 'ganador', 'ganaste', 'gratis', 'free', 'regalo', 'sorteo',
    'bono', 'bonus', 'descuento', 'oferta', 'promocion', 'promoción',
    'reembolso', 'refund', 'devolucion', 'devolución', 'subsidio', 'ayuda',
    'beca', 'vale', 'cupon', 'recompensa', 'reclamar', 'reclama'
  ],
  financiero: [
    'banco', 'bank', 'pago', 'payment', 'pagar', 'transferencia', 'transfer',
    'factura', 'invoice', 'recibo', 'deuda', 'multa', 'impuesto', 'tax',
    'wallet', 'billetera', 'seed', 'frase-semilla', 'mnemonic', 'privatekey',
    'llave-privada', 'kyc', 'airdrop', 'staking', 'metamask', 'ledger'
  ],
  paqueteria: [
    'envio', 'envío', 'paquete', 'package', 'entrega', 'delivery', 'aduana',
    'customs', 'tracking', 'rastreo', 'guia', 'guía', 'redelivery',
    'reprogramar', 'direccion-incorrecta'
  ]
};

export const NOMBRE_CEBO = {
  credencial: 'captura de credenciales', urgencia: 'presión por urgencia',
  cebo: 'promesa de recompensa', financiero: 'contexto financiero',
  paqueteria: 'entrega de paquete'
};

/* ══════════════════ Cargas ejecutables ══════════════════ */

export const ESQUEMAS_EJECUTABLES = new Set([
  'javascript:', 'vbscript:', 'data:', 'blob:', 'file:', 'about:',
  'chrome:', 'chrome-extension:', 'moz-extension:', 'jar:', 'view-source:',
  'resource:', 'ms-msdt:', 'search-ms:', 'ms-officecmd:', 'ms-appinstaller:'
]);

export const ESQUEMAS_PAGO = new Set([
  'bitcoin:', 'bitcoincash:', 'ethereum:', 'litecoin:', 'monero:', 'dogecoin:',
  'ripple:', 'solana:', 'tron:', 'upi:', 'spd:', 'pix:', 'yappy:', 'nequi:',
  'lightning:', 'lnurl:'
]);

export const EXT_EJECUTABLE = new Set([
  'exe', 'msi', 'msix', 'appx', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs',
  'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'psm1', 'hta', 'cpl', 'reg',
  'lnk', 'inf', 'jar', 'apk', 'aab', 'ipa', 'dmg', 'pkg', 'deb', 'rpm',
  'run', 'bin', 'sh', 'appimage'
]);

export const EXT_CONTENEDOR = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'img', 'cab',
  'ace', 'arj', 'lzh', 'z', 'vhd', 'vhdx'
]);

export const EXT_DOCUMENTO_MACRO = new Set([
  'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'xlam', 'ppam', 'sldm'
]);

/** Parámetros que suelen contener una segunda URL. */
export const PARAMS_REDIRECCION = [
  'url', 'uri', 'redirect', 'redirect_uri', 'redirect_url', 'redir',
  'next', 'dest', 'destination', 'destino', 'continue', 'return',
  'return_url', 'returnurl', 'returnto', 'goto', 'go', 'target', 'link',
  'out', 'forward', 'r', 'u', 'q', 'callback', 'checkout_url', 'image_url'
];

/** Parámetros que no deberían viajar nunca en un enlace de un QR. */
export const PARAMS_SENSIBLES = [
  'password', 'passwd', 'pwd', 'clave', 'contrasena', 'secret', 'api_key',
  'apikey', 'access_token', 'token', 'auth', 'session', 'sessionid',
  'jwt', 'otp', 'code', 'pin', 'cvv', 'card', 'tarjeta', 'cuenta', 'iban'
];

/** Prefijos de tarificación especial y numeración con historial de fraude. */
export const PREFIJOS_TEL_RIESGO = [
  ['+1900', 'tarificación especial en Norteamérica'],
  ['+1976', 'tarificación especial en Jamaica, usada en el fraude de la llamada perdida'],
  ['+1809', 'República Dominicana, usada en el fraude de la llamada perdida'],
  ['+1284', 'Islas Vírgenes Británicas, usada en el fraude de la llamada perdida'],
  ['+1473', 'Granada, usada en el fraude de la llamada perdida'],
  ['+1649', 'Islas Turcas y Caicos, usada en el fraude de la llamada perdida'],
  ['+1868', 'Trinidad y Tobago, usada en el fraude de la llamada perdida'],
  ['+232', 'Sierra Leona, destino frecuente de desvíos con costo'],
  ['+252', 'Somalia, destino frecuente de desvíos con costo'],
  ['+370', 'Lituania, destino frecuente de desvíos con costo'],
  ['+881', 'satelital, costo por minuto muy elevado'],
  ['+882', 'red internacional, costo por minuto muy elevado'],
  ['+883', 'red internacional, costo por minuto muy elevado']
];