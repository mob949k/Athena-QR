/**
 * Athena · scanner.js
 * Adquisición de imagen y decodificación. Aísla dos detalles del resto de la app:
 *   1. Qué motor decodifica (BarcodeDetector nativo, con jsQR como respaldo).
 *   2. El ciclo de vida de la cámara, que debe cerrarse siempre.
 *
 * Nada de esto toca la red. Todo ocurre en el dispositivo.
 */

const TAM_MAX = 1600;      // lado máximo al rasterizar una imagen subida
const INTERVALO_MS = 100;  // ~10 lecturas/s: suficiente y evita freír la batería

let detectorNativo = null;
let nativoProbado = false;

async function obtenerDetectorNativo() {
  if (nativoProbado) return detectorNativo;
  nativoProbado = true;
  try {
    if ('BarcodeDetector' in window) {
      const formatos = await window.BarcodeDetector.getSupportedFormats();
      if (formatos.includes('qr_code')) {
        detectorNativo = new window.BarcodeDetector({ formats: ['qr_code'] });
      }
    }
  } catch { detectorNativo = null; }
  return detectorNativo;
}

/** Motor en uso, para mostrarlo en la interfaz. */
export function motorActivo() {
  return detectorNativo ? 'nativo' : 'jsQR';
}

/** Decodifica desde cualquier fuente dibujable. Devuelve el texto o null. */
async function decodificar(fuente, ctx, ancho, alto) {
  const nativo = await obtenerDetectorNativo();
  if (nativo) {
    try {
      const res = await nativo.detect(fuente);
      if (res.length) return res[0].rawValue;
      return null;
    } catch { /* cae al respaldo */ }
  }
  if (typeof jsQR !== 'function') return null;
  const datos = ctx.getImageData(0, 0, ancho, alto);
  const codigo = jsQR(datos.data, ancho, alto, { inversionAttempts: 'attemptBoth' });
  return codigo ? codigo.data : null;
}

/* ────────────────────────── Imagen subida ────────────────────────── */

export async function leerArchivo(archivo) {
  if (!archivo) throw new Error('No se seleccionó ninguna imagen.');
  if (!archivo.type.startsWith('image/')) throw new Error('El archivo no es una imagen.');
  if (archivo.size > 20 * 1024 * 1024) throw new Error('La imagen supera los 20 MB.');

  const url = URL.createObjectURL(archivo);
  try {
    const img = await new Promise((res, rej) => {
      const i = new Image();
      i.onload = () => res(i);
      i.onerror = () => rej(new Error('No se pudo leer la imagen.'));
      i.src = url;
    });

    const escala = Math.min(1, TAM_MAX / Math.max(img.width, img.height));
    const lienzo = document.createElement('canvas');
    lienzo.width = Math.round(img.width * escala);
    lienzo.height = Math.round(img.height * escala);
    const ctx = lienzo.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(img, 0, 0, lienzo.width, lienzo.height);

    return await decodificar(lienzo, ctx, lienzo.width, lienzo.height);
  } finally {
    URL.revokeObjectURL(url);
  }
}

/* ──────────────────────────── Cámara ──────────────────────────── */

export class CamaraQR {
  /**
   * @param {HTMLVideoElement} video
   * @param {{onLectura:(t:string)=>void, onError:(e:Error)=>void, onEstado:(s:string)=>void}} eventos
   */
  constructor(video, eventos) {
    this.video = video;
    this.ev = eventos;
    this.stream = null;
    this.activa = false;
    this.rafId = null;
    this.ultima = 0;
    this.ocupado = false;

    this.lienzo = document.createElement('canvas');
    this.ctx = this.lienzo.getContext('2d', { willReadFrequently: true });

    // La cámara nunca debe quedar viva si la pestaña deja de verse.
    this._onVisibilidad = () => { if (document.hidden) this.detener(); };
    document.addEventListener('visibilitychange', this._onVisibilidad);
    window.addEventListener('pagehide', () => this.detener());
  }

  get soportada() {
    return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  }

  async iniciar() {
    if (this.activa) return;
    if (!window.isSecureContext) {
      throw new Error('La cámara solo funciona sobre HTTPS. Abre el sitio con una dirección https://');
    }
    if (!this.soportada) {
      throw new Error('Este navegador no permite el acceso a la cámara.');
    }

    this.ev.onEstado('iniciando');
    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
        audio: false
      });
    } catch (e) {
      this.ev.onEstado('inactiva');
      throw new Error(traducirErrorCamara(e));
    }

    this.video.srcObject = this.stream;
    await this.video.play().catch(() => {});
    await new Promise(res => {
      if (this.video.readyState >= 2) return res();
      this.video.addEventListener('loadeddata', res, { once: true });
    });

    this.lienzo.width = this.video.videoWidth || 640;
    this.lienzo.height = this.video.videoHeight || 480;
    this.activa = true;
    this.ev.onEstado('activa');
    this._bucle();
  }

  _bucle() {
    const paso = async (t) => {
      if (!this.activa) return;
      this.rafId = requestAnimationFrame(paso);
      if (this.ocupado || t - this.ultima < INTERVALO_MS) return;
      this.ultima = t;
      this.ocupado = true;
      try {
        this.ctx.drawImage(this.video, 0, 0, this.lienzo.width, this.lienzo.height);
        const texto = await decodificar(this.lienzo, this.ctx, this.lienzo.width, this.lienzo.height);
        if (texto && this.activa) {
          this.detener();
          this.ev.onLectura(texto);
        }
      } catch (e) {
        this.ev.onError(e);
      } finally {
        this.ocupado = false;
      }
    };
    this.rafId = requestAnimationFrame(paso);
  }

  detener() {
    this.activa = false;
    if (this.rafId) cancelAnimationFrame(this.rafId);
    this.rafId = null;
    if (this.stream) {
      this.stream.getTracks().forEach(p => p.stop());
      this.stream = null;
    }
    this.video.srcObject = null;
    this.ev.onEstado('inactiva');
  }
}

function traducirErrorCamara(e) {
  switch (e?.name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return 'Permiso denegado. Habilita la cámara para este sitio en los ajustes del navegador.';
    case 'NotFoundError':
    case 'DevicesNotFoundError':
      return 'No se detectó ninguna cámara en este dispositivo.';
    case 'NotReadableError':
      return 'Otra aplicación está usando la cámara. Ciérrala e inténtalo de nuevo.';
    case 'OverconstrainedError':
      return 'La cámara no admite la resolución solicitada.';
    default:
      return 'No se pudo abrir la cámara.';
  }
}