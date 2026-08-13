/**
 * Athena · lib/marcadores.js
 * Conjunto de caracteres que se resaltan en la lectura forense.
 *
 * Se deriva del mapa de confundibles, pero excluye el latino extendido:
 * marcar la «ó» de «Reunión» sería ruido, mientras que marcar la «о»
 * cirílica de «gооgle» es exactamente el punto.
 */

import { CONFUNDIBLES } from '../data/confusables.js';

export const HOMOGLIFOS_ACTIVOS = (() => {
  const s = new Set();
  for (const c of CONFUNDIBLES.keys()) {
    const cp = c.codePointAt(0);
    if (cp < 0x0100) continue;                    // latino básico y acentos
    if (cp >= 0x0100 && cp <= 0x024F) continue;   // latino extendido A/B
    s.add(c);
  }
  return s;
})();