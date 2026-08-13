/**
 * Athena · ui.js
 * Presentación. Regla inquebrantable de este archivo: los datos escaneados
 * jamás se insertan con innerHTML. Solo textContent y createElement.
 */

import { VEREDICTO, ETIQUETA_TIPO, SEVERIDAD } from './analyzer.js';

const TEXTO_VEREDICTO = {
  seguro:     { titulo: 'Sin señales de riesgo',   simbolo: '◈' },
  precaucion: { titulo: 'Revísalo antes de abrir', simbolo: '◭' },
  sospechoso: { titulo: 'Señales claras de fraude', simbolo: '▲' },
  peligro:    { titulo: 'No lo abras',             simbolo: '◆' }
};

const ETIQUETA_SEVERIDAD = {
  critica: 'Crítico', alta: 'Alto', media: 'Medio', baja: 'Bajo', info: 'Dato'
};

const TITULO_MARCA = {
  dominio: 'Dominio registrado: es lo único que decide a dónde vas realmente',
  homo: 'Letra de otro alfabeto que imita a una latina',
  noascii: 'Carácter fuera del alfabeto latino básico',
  cod: 'Secuencia codificada en hexadecimal',
  arroba: 'El navegador ignora todo lo escrito antes de este símbolo',
  puny: 'Prefijo de dominio internacionalizado',
  invis: 'Carácter invisible: no se ve, pero cuenta para el navegador'
};

const LEYENDA = [
  ['dominio', 'dominio real'], ['homo', 'letra impostora'], ['arroba', 'anula lo anterior'],
  ['puny', 'alfabeto no latino'], ['cod', 'codificado'], ['invis', 'invisible'],
  ['noascii', 'fuera del latino']
];

const $ = sel => document.querySelector(sel);

export const el = {
  video: $('#video'),
  visor: $('#visor'),
  btnCamara: $('#btnCamara'),
  btnArchivo: $('#btnArchivo'),
  inputArchivo: $('#inputArchivo'),
  resultado: $('#resultado'),
  vacio: $('#vacio'),
  veredicto: $('#veredicto'),
  veredictoSimbolo: $('#veredictoSimbolo'),
  veredictoTitulo: $('#veredictoTitulo'),
  veredictoTipo: $('#veredictoTipo'),
  medidorBarra: $('#medidorBarra'),
  medidorValor: $('#medidorValor'),
  lectura: $('#lectura'),
  hallazgos: $('#hallazgos'),
  btnCopiar: $('#btnCopiar'),
  btnAbrir: $('#btnAbrir'),
  btnNuevo: $('#btnNuevo'),
  aviso: $('#aviso'),
  historial: $('#historial'),
  listaHistorial: $('#listaHistorial'),
  motor: $('#motor')
};

/* ─────────────────────────── Utilidades ─────────────────────────── */

const crear = (etiqueta, clase, texto) => {
  const n = document.createElement(etiqueta);
  if (clase) n.className = clase;
  if (texto != null) n.textContent = texto;
  return n;
};

export function estadoCamara(estado) {
  const etiqueta = el.btnCamara.querySelector('.rotulo');
  el.visor.dataset.estado = estado;
  el.btnCamara.setAttribute('aria-pressed', String(estado === 'activa'));
  etiqueta.textContent = estado === 'activa' ? 'Detener cámara'
    : estado === 'iniciando' ? 'Abriendo…' : 'Activar cámara';
  el.btnCamara.disabled = estado === 'iniciando';
}

export function aviso(mensaje, tono = 'error') {
  el.aviso.textContent = mensaje || '';
  el.aviso.dataset.tono = tono;
  el.aviso.hidden = !mensaje;
}

export function prefiereQuietud() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/* ─────────────────────── Lectura forense ─────────────────────── */

function pintarLectura(anotacion) {
  el.lectura.textContent = '';
  const frag = document.createDocumentFragment();
  const usados = new Set();

  for (const tramo of anotacion) {
    if (!tramo.k) {
      frag.appendChild(document.createTextNode(tramo.t));
      continue;
    }
    usados.add(tramo.k);
    const m = crear('mark', `marca marca--${tramo.k}`, tramo.t);
    m.title = TITULO_MARCA[tramo.k] || '';
    frag.appendChild(m);
  }
  el.lectura.appendChild(frag);

  // Leyenda: solo de los tipos que realmente aparecen en esta lectura.
  const leyenda = document.querySelector('#leyenda');
  if (leyenda) {
    leyenda.textContent = '';
    leyenda.hidden = usados.size === 0;
    for (const [clave, texto] of LEYENDA) {
      if (!usados.has(clave)) continue;
      const chip = crear('span', 'ley');
      chip.appendChild(crear('span', `ley__punto ley__punto--${clave}`));
      chip.appendChild(crear('span', null, texto));
      leyenda.appendChild(chip);
    }
  }
}

/* ───────────────────────── Hallazgos ───────────────────────── */

function nodoHallazgo(h) {
  const li = crear('li', `hallazgo hallazgo--${h.severidad}`);
  li.appendChild(crear('span', 'chip', ETIQUETA_SEVERIDAD[h.severidad]));

  const cuerpo = crear('div');
  cuerpo.appendChild(crear('p', 'hallazgo__titulo', h.titulo));
  cuerpo.appendChild(crear('p', 'hallazgo__detalle', h.detalle));
  if (h.tecnica) cuerpo.appendChild(crear('p', 'hallazgo__tecnica', `Técnica: ${h.tecnica}`));
  li.appendChild(cuerpo);
  return li;
}

function nodoAnidado(informe, nivel = 1) {
  const li = crear('li', 'anidado');
  li.dataset.nivel = informe.veredicto;

  const cab = crear('div', 'anidado__cabecera');
  cab.appendChild(crear('span', 'anidado__flecha', '↳'));
  cab.appendChild(crear('span', 'anidado__rotulo',
    nivel === 1 ? 'Destino final del enlace' : 'Y ese a su vez lleva a'));
  cab.appendChild(crear('span', 'anidado__nivel', TEXTO_VEREDICTO[informe.veredicto].titulo));
  li.appendChild(cab);

  li.appendChild(crear('p', 'anidado__url', informe.bruto));

  const sub = crear('ul', 'hallazgos hallazgos--anidados');
  for (const h of informe.hallazgos) {
    if (h.severidad === SEVERIDAD.INFO) continue;
    sub.appendChild(nodoHallazgo(h));
  }
  if (sub.childElementCount) li.appendChild(sub);
  for (const nieto of informe.anidados) sub.appendChild(nodoAnidado(nieto, nivel + 1));

  return li;
}

function pintarHallazgos(informe) {
  el.hallazgos.textContent = '';

  for (const grupo of informe.tacticas) {
    const li = crear('li', 'tactica');
    li.appendChild(crear('p', 'tactica__nombre', grupo.nombre));
    const ul = crear('ul', 'hallazgos');
    for (const h of grupo.hallazgos) ul.appendChild(nodoHallazgo(h));
    li.appendChild(ul);
    el.hallazgos.appendChild(li);
  }
  for (const anidado of informe.anidados) {
    el.hallazgos.appendChild(nodoAnidado(anidado));
  }
}

/* ──────────────────────── Informe completo ──────────────────────── */

export function mostrarInforme(informe) {
  const v = TEXTO_VEREDICTO[informe.veredicto];

  el.vacio.hidden = true;
  el.resultado.hidden = false;
  el.veredicto.dataset.nivel = informe.veredicto;
  el.veredictoSimbolo.textContent = v.simbolo;
  el.veredictoTitulo.textContent = v.titulo;
  el.veredictoTipo.textContent = ETIQUETA_TIPO[informe.tipo] || 'Contenido';

  el.medidorBarra.style.setProperty('--pct', `${informe.puntaje}%`);
  el.medidorBarra.dataset.nivel = informe.veredicto;
  el.medidorBarra.setAttribute('aria-valuenow', String(informe.puntaje));

  const nTac = informe.tacticas.filter(g => g.categoria !== 'contexto').length;
  el.medidorValor.textContent = informe.criticos
    ? `${informe.criticos} señal${informe.criticos > 1 ? 'es' : ''} de alto riesgo en ${nTac} táctica${nTac > 1 ? 's' : ''}`
    : nTac
      ? 'Señales menores detectadas'
      : 'Ninguna señal detectada';

  pintarLectura(informe.anotacion);
  pintarHallazgos(informe);

  // Solo un veredicto limpio permite abrir sin confirmación.
  const directo = informe.veredicto === VEREDICTO.SEGURO
    || informe.veredicto === VEREDICTO.PRECAUCION;
  el.btnAbrir.hidden = !informe.url;
  el.btnAbrir.dataset.confirmar = directo ? 'no' : 'si';
  el.btnAbrir.querySelector('.rotulo').textContent =
    directo ? 'Abrir enlace' : 'Abrir de todos modos';
  el.btnAbrir.classList.toggle('btn--peligro', !directo);

  el.resultado.focus({ preventScroll: true });
  el.resultado.scrollIntoView({
    behavior: prefiereQuietud() ? 'auto' : 'smooth', block: 'nearest'
  });
}

export function limpiarInforme() {
  el.resultado.hidden = true;
  el.vacio.hidden = false;
  aviso('');
}

/* ───────────────────────── Historial ───────────────────────── */

export function pintarHistorial(items, onSeleccion) {
  el.historial.hidden = items.length === 0;
  el.listaHistorial.textContent = '';

  items.forEach((item, i) => {
    const li = crear('li');
    const btn = crear('button', 'entrada');
    btn.type = 'button';
    btn.dataset.nivel = item.veredicto;

    const punto = crear('span', 'entrada__punto');
    punto.setAttribute('aria-hidden', 'true');
    btn.appendChild(punto);
    btn.appendChild(crear('span', 'entrada__texto',
      item.bruto.length > 64 ? item.bruto.slice(0, 64) + '…' : item.bruto));
    btn.appendChild(crear('span', 'entrada__nivel', TEXTO_VEREDICTO[item.veredicto].titulo));

    btn.addEventListener('click', () => onSeleccion(i));
    li.appendChild(btn);
    el.listaHistorial.appendChild(li);
  });
}