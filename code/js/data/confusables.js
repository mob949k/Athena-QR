/**
 * Athena · data/confusables.js
 *
 * Base para la detección de homógrafos siguiendo el espíritu de UTS #39.
 * La idea: reducir cualquier cadena a un «esqueleto» — la forma latina que el
 * ojo humano percibe — y comparar esqueletos en vez de cadenas.
 *
 *   раураl.com  →  esqueleto  paypal.com  →  coincide con marca  →  ATAQUE
 *
 * Una comparación por distancia de edición nunca detecta esto: las letras
 * cirílicas no se parecen a las latinas, son bytes completamente distintos.
 */

/* Caracteres invisibles o de control de dirección. Se eliminan siempre:
   su única función en un dominio o nombre de archivo es engañar. */
export const INVISIBLES = new RegExp(
  '[' +
  '\u00AD' +            // guion suave
  '\u034F' +            // combinador de agrupación
  '\u061C' +            // marca árabe de dirección
  '\u115F\u1160' +      // llenadores hangul
  '\u17B4\u17B5' +      // vocales jemer invisibles
  '\u180E' +            // separador de vocal mongol
  '\u200B-\u200F' +     // espacios de ancho cero y marcas LTR/RTL
  '\u202A-\u202E' +     // anulaciones bidireccionales (truco del .exe→.txt)
  '\u2060-\u2064' +     // uniones de ancho cero
  '\u206A-\u206F' +     // selección de forma obsoleta
  '\u3164' +            // llenador hangul
  '\uFE00-\uFE0F' +     // selectores de variación
  '\uFEFF' +            // BOM
  '\uFFA0' +            // llenador hangul de ancho medio
  ']', 'g'
);

/* Caracteres que el navegador trata como separador de etiquetas de dominio.
   `google。com` funciona: IDNA los normaliza todos a un punto. */
export const PUNTOS_ALTERNOS = /[\u3002\uFF0E\uFF61\u2024\u06D4\u1362\uA4F8]/g;

/* Caracteres que el navegador trata como barra de ruta. */
export const BARRAS_ALTERNAS = /[\u2044\u2215\uFF0F\u29F8]/g;

/* Rangos de escritura, para detectar mezcla de alfabetos dentro de una etiqueta. */
export const ESCRITURAS = [
  ['latino', /[A-Za-z]/],
  ['cirílico', /[\u0400-\u04FF\u0500-\u052F\u2DE0-\u2DFF\uA640-\uA69F]/],
  ['griego', /[\u0370-\u03FF\u1F00-\u1FFF]/],
  ['armenio', /[\u0530-\u058F]/],
  ['hebreo', /[\u0590-\u05FF]/],
  ['árabe', /[\u0600-\u06FF\u0750-\u077F]/],
  ['cherokee', /[\u13A0-\u13FF\uAB70-\uABBF]/],
  ['han', /[\u4E00-\u9FFF\u3400-\u4DBF]/],
  ['kana', /[\u3040-\u30FF]/],
  ['hangul', /[\uAC00-\uD7AF\u1100-\u11FF]/],
  ['tailandés', /[\u0E00-\u0E7F]/],
  ['devanagari', /[\u0900-\u097F]/]
];

/**
 * Mapa de confundibles → latino.
 * Formato compacto: cada entrada es "destino:origen1origen2…".
 * Se expande a un Map en tiempo de carga.
 */
const CRUDO = [
  // ── Cirílico ──────────────────────────────────────────────────────────
  'a:аӑӓәәӕ', 'b:ЬЪвбвь', 'c:сϲс', 'd:ԁđ', 'e:еёэєҽҿ', 'f:ғ',
  'g:ԍ', 'h:һнԋҥ', 'i:іїıΙ', 'j:јʝ', 'k:кқҟҝ', 'l:ӏĺ',
  'm:мӎ', 'n:пԥийлñ', 'o:оθөѳфӧ', 'p:рҏ', 'q:ԛ', 'r:гґя',
  's:ѕʂ', 't:тҭ', 'u:цүұџи', 'v:ѵ', 'w:ԝшщ', 'x:хжӿ',
  'y:уўұүѵ', 'z:зҙ',
  // Mayúsculas cirílicas (se minusculizan después, pero el mapeo debe existir)
  'A:А', 'B:ВЬ', 'C:С', 'E:ЕЁЄ', 'H:Н', 'I:І', 'J:Ј', 'K:К',
  'M:М', 'O:ОӦѲ', 'P:Р', 'S:Ѕ', 'T:Т', 'X:Х', 'Y:УЎ',

  // ── Griego ────────────────────────────────────────────────────────────
  'a:αά', 'b:βϐ', 'c:ϲςсϛ', 'd:δ', 'e:εέϵ', 'g:γ', 'h:ηή',
  'i:ιίϊΐ', 'k:κϰ', 'l:λ', 'm:μϻ', 'n:ηνπ', 'o:οόσωώθ',
  'p:ρϱπ', 'r:ր', 's:ѕ', 't:τ', 'u:υύϋ', 'v:ν', 'w:ωώψ',
  'x:χ', 'y:γψ', 'z:ζ',
  'A:Α', 'B:Β', 'E:Ε', 'H:Η', 'I:Ι', 'K:Κ', 'M:Μ', 'N:Ν',
  'O:ΟΘ', 'P:Ρ', 'T:Τ', 'X:Χ', 'Y:Υ', 'Z:Ζ',

  // ── Armenio ───────────────────────────────────────────────────────────
  'q:զգք', 'o:օ', 'n:ոռղդ', 'u:մսև', 'h:հի', 'g:ց', 'j:յ',
  'l:լ', 'w:ա', 'p:պ', 'f:ֆ', 's:ս',

  // ── Cherokee (script completo confundible con latino) ─────────────────
  'a:Ꭺ', 'b:Ᏼ', 'c:Ꮯ', 'd:Ꭰ', 'e:Ꭼ', 'g:Ꮐ', 'h:Ꮋ', 'i:Ꭵ',
  'j:Ꭻ', 'k:Ꮶ', 'l:Ꮮ', 'm:Ꮇ', 'p:Ꮲ', 'r:Ꮢ', 's:Ꮪ', 't:Ꭲ',
  'v:Ꮩ', 'w:Ꮃ', 'y:Ꭹ', 'z:Ꮓ',

  // ── Latino extendido y matemático ─────────────────────────────────────
  'a:àáâãäåāăąǎ', 'c:çćĉċčϲ', 'd:ďđðḍ', 'e:èéêëēĕėęěɇ',
  'g:ĝğġģǥ', 'h:ĥħḥ', 'i:ìíîïĩīĭįǐɨ', 'j:ĵɉ', 'k:ķĸ',
  'l:ĺļľŀłℓ', 'n:ñńņňŉŋɲ', 'o:òóôõöøōŏőǒơ', 'r:ŕŗřɍ',
  's:śŝşšſșṣ', 't:ţťŧțṭ', 'u:ùúûüũūŭůűųưǔ', 'w:ŵ',
  'y:ýÿŷɏ', 'z:źżž',

  // ── Dígitos y símbolos que imitan letras ──────────────────────────────
  'o:0ΟОօ', 'l:1|Ɩ', 'i:1ｌ', 'z:2', 'e:3', 'a:4@', 's:5$',
  'b:6', 't:7', 'g:9',

  // ── Fullwidth (NFKD ya cubre la mayoría, se refuerza por seguridad) ───
  'a:ａ', 'b:ｂ', 'c:ｃ', 'd:ｄ', 'e:ｅ', 'g:ｇ', 'i:ｉ',
  'l:ｌ', 'm:ｍ', 'n:ｎ', 'o:ｏ', 'p:ｐ', 'r:ｒ', 's:ｓ',
  't:ｔ', 'u:ｕ', 'y:ｙ'
];

export const CONFUNDIBLES = (() => {
  const m = new Map();
  for (const linea of CRUDO) {
    const i = linea.indexOf(':');
    const destino = linea.slice(0, i);
    for (const c of linea.slice(i + 1)) if (!m.has(c)) m.set(c, destino);
  }
  return m;
})();

/**
 * Secuencias multicarácter que imitan una sola letra.
 * `paypaI` no engaña a nadie; `rnicrosoft.com` sí.
 */
export const SECUENCIAS = [
  [/rn/g, 'm'], [/vv/g, 'w'], [/cl/g, 'd'], [/ii/g, 'u'],
  [/nn/g, 'm'], [/rl/g, 'd'], [/lj/g, 'y']
];

/** ¿Qué escrituras aparecen en el texto? */
export function escrituras(texto) {
  const halladas = [];
  for (const [nombre, re] of ESCRITURAS) if (re.test(texto)) halladas.push(nombre);
  return halladas;
}