/**
 * Athena · app.js
 * Controlador. Une adquisición, análisis y presentación. No contiene reglas
 * de seguridad ni marcado: solo decide qué ocurre y cuándo.
 */

import { analizar, VEREDICTO } from './analyzer.js';
import { CamaraQR, leerArchivo, motorActivo } from './scanner.js';
import * as ui from './ui.js';

const HISTORIAL_MAX = 8;
const historial = [];   // solo en memoria: se pierde al cerrar la pestaña, a propósito

let camara = null;
let informeActual = null;

/* ─────────────────────────── Flujo central ─────────────────────────── */

function procesar(texto) {
  ui.aviso('');
  informeActual = analizar(texto);
  ui.mostrarInforme(informeActual);

  if (historial[0]?.bruto !== informeActual.bruto) {
    historial.unshift(informeActual);
    if (historial.length > HISTORIAL_MAX) historial.pop();
  }
  ui.pintarHistorial(historial, i => {
    informeActual = historial[i];
    ui.mostrarInforme(informeActual);
  });
}

/* ─────────────────────────── Cámara ─────────────────────────── */

function crearCamara() {
  return new CamaraQR(ui.el.video, {
    onLectura: procesar,
    onEstado: estado => {
      ui.estadoCamara(estado);
      if (estado === 'activa') ui.el.motor.textContent = `Motor: ${motorActivo()}`;
    },
    onError: e => ui.aviso(e.message || 'Fallo al leer la imagen de la cámara.')
  });
}

ui.el.btnCamara.addEventListener('click', async () => {
  camara ??= crearCamara();
  if (camara.activa) { camara.detener(); return; }
  ui.aviso('');
  try {
    await camara.iniciar();
  } catch (e) {
    ui.aviso(e.message);
  }
});

/* ─────────────────────────── Imagen ─────────────────────────── */

ui.el.btnArchivo.addEventListener('click', () => ui.el.inputArchivo.click());

ui.el.inputArchivo.addEventListener('change', async ev => {
  const archivo = ev.target.files?.[0];
  ev.target.value = '';            // permite volver a elegir el mismo archivo
  if (!archivo) return;
  camara?.detener();
  ui.aviso('Analizando la imagen…', 'neutro');
  try {
    const texto = await leerArchivo(archivo);
    if (texto) procesar(texto);
    else ui.aviso('No se encontró ningún código QR en la imagen. Prueba con una foto más nítida o recortada.');
  } catch (e) {
    ui.aviso(e.message);
  }
});

/* Arrastrar y soltar sobre el visor */
['dragenter', 'dragover'].forEach(t =>
  ui.el.visor.addEventListener(t, e => { e.preventDefault(); ui.el.visor.dataset.soltar = 'si'; }));
['dragleave', 'drop'].forEach(t =>
  ui.el.visor.addEventListener(t, () => { delete ui.el.visor.dataset.soltar; }));
ui.el.visor.addEventListener('drop', e => {
  e.preventDefault();
  const archivo = e.dataTransfer?.files?.[0];
  if (!archivo) return;
  const dt = new DataTransfer();
  dt.items.add(archivo);
  ui.el.inputArchivo.files = dt.files;
  ui.el.inputArchivo.dispatchEvent(new Event('change'));
});

/* Pegar una imagen del portapapeles */
document.addEventListener('paste', e => {
  const item = [...(e.clipboardData?.items || [])].find(i => i.type.startsWith('image/'));
  if (!item) return;
  const dt = new DataTransfer();
  dt.items.add(item.getAsFile());
  ui.el.inputArchivo.files = dt.files;
  ui.el.inputArchivo.dispatchEvent(new Event('change'));
});

/* ─────────────────────────── Acciones ─────────────────────────── */

ui.el.btnCopiar.addEventListener('click', async () => {
  if (!informeActual) return;
  try {
    await navigator.clipboard.writeText(informeActual.bruto);
    const r = ui.el.btnCopiar.querySelector('.rotulo');
    r.textContent = 'Copiado';
    setTimeout(() => { r.textContent = 'Copiar contenido'; }, 1600);
  } catch {
    ui.aviso('El navegador bloqueó el portapapeles. Selecciona el texto manualmente.');
  }
});

ui.el.btnAbrir.addEventListener('click', () => {
  if (!informeActual?.url) return;
  const destino = informeActual.url.href;

  // Athena nunca navega sola. Ante veredicto de peligro, exige confirmación explícita.
  if (ui.el.btnAbrir.dataset.confirmar === 'si') {
    const ok = window.confirm(
      `Athena encontró ${informeActual.criticos} señal(es) de alto riesgo en este destino.\n\n` +
      `${destino}\n\n` +
      `Si continúas, podrías entregar credenciales o datos bancarios a un tercero. ` +
      `¿Abrir de todos modos?`
    );
    if (!ok) return;
  }
  window.open(destino, '_blank', 'noopener,noreferrer');
});

ui.el.btnNuevo.addEventListener('click', () => {
  informeActual = null;
  ui.limpiarInforme();
  ui.el.btnCamara.focus();
});

/* ─────────────────────────── Arranque ─────────────────────────── */

ui.estadoCamara('inactiva');
ui.el.motor.textContent = 'Análisis local · nada sale de tu dispositivo';

// Permite compartir un resultado por URL sin exponerlo a un servidor:
// el fragmento (#) nunca viaja en la petición HTTP.
if (location.hash.length > 1) {
  try { procesar(decodeURIComponent(location.hash.slice(1))); } catch { /* ignorar */ }
}