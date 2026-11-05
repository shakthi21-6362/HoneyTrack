/**
 * SpecularButton - Hardware-Accelerated WebGL Border Shader Button
 * Provides silky smooth specular highlight rim tracking, dynamic mouse proximity glow,
 * and high-refresh-rate reactive rendering.
 */
(() => {
  'use strict';

  const PAD = 24;
  const TAU = Math.PI * 2;

  const VERTEX = `#version 300 es
in vec2 aPosition;
void main() {
  gl_Position = vec4(aPosition, 0.0, 1.0);
}`;

  const FRAGMENT = `#version 300 es
precision highp float;
uniform vec2 uCenter;
uniform vec2 uHalf;
uniform float uRadius;
uniform float uPx;
uniform float uSpot;
uniform vec2 uEntry;
uniform vec3 uLineColor;
uniform vec3 uBaseColor;
uniform float uIntensity;
uniform vec2 uWindow;
uniform float uThickness;
uniform float uGlow;
out vec4 outColor;

float roundedBox(vec2 p, vec2 b, float r) {
  vec2 q = abs(p) - b + r;
  return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r;
}

float loopPosition(vec2 p, vec2 b, float r) {
  vec2 inner = b - r;
  float arc = 1.5707963 * r;
  float quarter = inner.x + inner.y + arc;
  vec2 a = abs(p);
  vec2 q = a - inner;
  float s = q.x > 0.0 && q.y > 0.0
    ? inner.y + atan(q.y, q.x) * r
    : (q.x > q.y ? min(a.y, inner.y) : inner.y + arc + inner.x - min(a.x, inner.x));
  if (p.x < 0.0) s = p.y >= 0.0 ? 2.0 * quarter - s : 2.0 * quarter + s;
  else if (p.y < 0.0) s = 4.0 * quarter - s;
  return s / max(4.0 * quarter, 0.0001);
}

float lobe(float position, float center) {
  float gap = abs(fract(position - center + 0.5) - 0.5);
  return 1.0 - smoothstep(uWindow.x, uWindow.x + uWindow.y, gap);
}

void main() {
  vec2 p = gl_FragCoord.xy - uCenter;
  float d = roundedBox(p, uHalf, uRadius);
  float position = loopPosition(p, uHalf, uRadius);
  float key = lobe(position, uSpot);
  float back = lobe(position, uSpot + 0.5);
  float streak = key + back * 0.45;
  float width = max(uThickness * uPx * mix(1.0, max(key, back), 0.6), 0.35);
  float band = smoothstep(-width - 0.6, -width + 0.6, d) * (1.0 - smoothstep(-0.6, 0.6, d));
  float hair = smoothstep(-uPx - 0.6, -uPx + 0.6, d) * (1.0 - smoothstep(-0.6, 0.6, d));
  float inside = 1.0 - smoothstep(-0.6, 0.6, d);
  vec2 pool = (p - uEntry) / (uHalf.y * vec2(1.6, 1.1));
  float glow = streak * 0.2 * exp(-abs(d + width * 0.5) / (5.0 * uPx)) + inside * 0.08 * exp(-dot(pool, pool));
  float light = clamp((band * streak + glow * uGlow) * uIntensity, 0.0, 1.0);
  vec4 base = vec4(uBaseColor, 1.0) * hair * 0.6;
  outColor = vec4(uLineColor, 1.0) * light + base * (1.0 - light);
}`;

  const UNIFORMS = [
    'uCenter',
    'uHalf',
    'uRadius',
    'uPx',
    'uSpot',
    'uEntry',
    'uLineColor',
    'uBaseColor',
    'uIntensity',
    'uWindow',
    'uThickness',
    'uGlow'
  ];

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const wrap = value => value - Math.floor(value);

  const loopPosition = (x, y, halfX, halfY, r) => {
    const innerX = halfX - r;
    const innerY = halfY - r;
    const arc = (Math.PI / 2) * r;
    const quarter = innerX + innerY + arc;
    const ax = Math.abs(x);
    const ay = Math.abs(y);
    const qx = ax - innerX;
    const qy = ay - innerY;
    let s;
    if (qx > 0 && qy > 0) s = innerY + Math.atan2(qy, qx) * r;
    else if (qx > qy) s = Math.min(ay, innerY);
    else s = innerY + arc + innerX - Math.min(ax, innerX);
    if (x < 0) s = y >= 0 ? 2 * quarter - s : 2 * quarter + s;
    else if (y < 0) s = 4 * quarter - s;
    return wrap(s / Math.max(4 * quarter, 0.0001));
  };

  const rimPoint = (position, halfX, halfY, r) => {
    const innerX = halfX - r;
    const innerY = halfY - r;
    const arc = (Math.PI / 2) * r;
    const quarter = innerX + innerY + arc;
    let s = wrap(position) * 4 * quarter;
    let signX = 1;
    let signY = 1;
    if (s > 3 * quarter) {
      s = 4 * quarter - s;
      signY = -1;
    } else if (s > 2 * quarter) {
      s -= 2 * quarter;
      signX = -1;
      signY = -1;
    } else if (s > quarter) {
      s = 2 * quarter - s;
      signX = -1;
    }
    let x = innerX - (s - innerY - arc);
    let y = halfY;
    if (s <= innerY) {
      x = halfX;
      y = s;
    } else if (s <= innerY + arc) {
      const angle = (s - innerY) / Math.max(r, 0.0001);
      x = innerX + Math.cos(angle) * r;
      y = innerY + Math.sin(angle) * r;
    }
    return [x * signX, y * signY];
  };

  const compileShader = (gl, type, source) => {
    const shader = gl.createShader(type);
    if (!shader) return null;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return shader;
    console.warn('[SpecularButton] Shader compile error:', gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    return null;
  };

  const linkProgram = gl => {
    const vertex = compileShader(gl, gl.VERTEX_SHADER, VERTEX);
    const fragment = compileShader(gl, gl.FRAGMENT_SHADER, FRAGMENT);
    const program = gl.createProgram();
    if (!vertex || !fragment || !program) return null;
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.bindAttribLocation(program, 0, 'aPosition');
    gl.linkProgram(program);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (gl.getProgramParameter(program, gl.LINK_STATUS)) return program;
    console.warn('[SpecularButton] Program link error:', gl.getProgramInfoLog(program));
    gl.deleteProgram(program);
    return null;
  };

  // Shared pointer tracker for maximum performance and zero listener duplication
  const globalPointer = {
    x: 0,
    y: 0,
    known: false,
    listeners: new Set()
  };

  let pointerInitialized = false;
  const initGlobalPointer = () => {
    if (pointerInitialized || typeof window === 'undefined') return;
    pointerInitialized = true;

    const onPointerMove = event => {
      globalPointer.x = event.clientX;
      globalPointer.y = event.clientY;
      globalPointer.known = true;
      for (const fn of globalPointer.listeners) fn();
    };

    const onPointerEnd = event => {
      if (event.pointerType === 'mouse') return;
      globalPointer.known = false;
      for (const fn of globalPointer.listeners) fn();
    };

    const onPointerLeave = () => {
      globalPointer.known = false;
      for (const fn of globalPointer.listeners) fn();
    };

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('pointerup', onPointerEnd, { passive: true });
    window.addEventListener('pointercancel', onPointerEnd, { passive: true });
    document.documentElement.addEventListener('pointerleave', onPointerLeave);
  };

  // Color parser helper
  const colorProbe = typeof document !== 'undefined'
    ? document.createElement('canvas').getContext('2d', { willReadFrequently: true })
    : null;
  const colorCache = new Map();

  const toRgb = value => {
    if (colorCache.has(value)) return colorCache.get(value);
    let rgb = [1, 1, 1];
    if (colorProbe) {
      colorProbe.clearRect(0, 0, 1, 1);
      colorProbe.fillStyle = '#000000';
      colorProbe.fillStyle = value;
      colorProbe.fillRect(0, 0, 1, 1);
      const [r, g, b] = colorProbe.getImageData(0, 0, 1, 1).data;
      rgb = [r / 255, g / 255, b / 255];
    }
    colorCache.set(value, rgb);
    return rgb;
  };

  /**
   * Attach SpecularButton engine to a DOM button or anchor element.
   */
  function attachSpecularButton(button, options = {}) {
    if (!button || button._specularAttached) return button;
    initGlobalPointer();

    const config = Object.assign({
      radius: 6,
      lineColor: '#ffffff',
      baseColor: '#525252',
      intensity: 1.2,
      idleIntensity: 0.35,
      shineSize: 14,
      shineFade: 36,
      thickness: 1.3,
      glow: 1.2,
      speed: 0.35,
      followMouse: true,
      proximity: 250,
      autoAnimate: false,
      disabled: false
    }, options);

    // Ensure DOM structure has canvas and label container
    let canvas = button.querySelector('canvas.specular-button__light');
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.className = 'specular-button__light';
      canvas.setAttribute('aria-hidden', 'true');

      let label = button.querySelector('.specular-button__label');
      if (!label) {
        label = document.createElement('span');
        label.className = 'specular-button__label';
        while (button.firstChild) {
          label.appendChild(button.firstChild);
        }
        button.appendChild(canvas);
        button.appendChild(label);
      } else {
        button.insertBefore(canvas, label);
      }
    }

    button.classList.add('specular-button');
    button.style.setProperty('--sb-radius', `${config.radius}px`);

    const gl = canvas.getContext('webgl2', {
      alpha: true,
      premultipliedAlpha: true,
      antialias: false,
      depth: false,
      stencil: false
    });

    if (!gl) {
      console.info('[SpecularButton] WebGL2 not supported; falling back to clean CSS styling.');
      button._specularAttached = true;
      return button;
    }

    const program = linkProgram(gl);
    if (!program) {
      button._specularAttached = true;
      return button;
    }

    const uniforms = {};
    for (const name of UNIFORMS) {
      uniforms[name] = gl.getUniformLocation(program, name);
    }

    const buffer = gl.createBuffer();
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    gl.bindVertexArray(null);

    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    const view = { width: 1, height: 1, ratio: 1 };
    const state = { spot: 0, level: 0, press: 0, ready: false };
    let raf = 0;
    let last = 0;
    let visible = true;
    let cachedRect = null;
    let rectStale = true;

    const cornerRadius = s => Math.min(s.radius, view.width / 2, view.height / 2);

    const restSpot = s => {
      const r = cornerRadius(s);
      const inset = r * (1 - Math.SQRT1_2);
      return loopPosition(inset - view.width / 2, view.height / 2 - inset, view.width / 2, view.height / 2, r);
    };

    const getButtonRect = () => {
      if (rectStale || !cachedRect) {
        cachedRect = button.getBoundingClientRect();
        rectStale = false;
      }
      return cachedRect;
    };

    const aim = s => {
      if (!s.followMouse || s.disabled || !globalPointer.known) return null;
      const rect = getButtonRect();
      const scale = rect.width / view.width || 1;
      const halfX = view.width / 2;
      const halfY = view.height / 2;
      const x = (globalPointer.x - rect.left - rect.width / 2) / scale;
      const y = (rect.top + rect.height / 2 - globalPointer.y) / scale;
      const distance = Math.hypot(Math.max(Math.abs(x) - halfX, 0), Math.max(Math.abs(y) - halfY, 0));
      const t = clamp(1 - distance / s.proximity, 0, 1);
      const near = t * t * (3 - 2 * t);
      const nearest = loopPosition(x, y, halfX, halfY, cornerRadius(s));
      if (distance > 0) return { spot: nearest, near };
      const depth = clamp(Math.min(halfX - Math.abs(x), halfY - Math.abs(y)) / (halfY * 0.8), 0, 1);
      const sway = restSpot(s) - (x / halfX) * 0.06 - (y / halfY) * 0.02;
      const offset = sway - nearest - Math.round(sway - nearest);
      return { spot: wrap(nearest + offset * depth * depth * (3 - 2 * depth)), near };
    };

    const draw = s => {
      const { width, height } = view;
      const scaleX = canvas.width / (width + PAD * 2);
      const scaleY = canvas.height / (height + PAD * 2);

      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.useProgram(program);

      gl.uniform2f(uniforms.uCenter, (PAD + width / 2) * scaleX, (PAD + height / 2) * scaleY);
      gl.uniform2f(uniforms.uHalf, (width / 2) * scaleX, (height / 2) * scaleY);
      gl.uniform1f(uniforms.uRadius, Math.min(s.radius, width / 2, height / 2) * scaleX);
      gl.uniform1f(uniforms.uPx, view.ratio);

      const r = Math.min(s.radius, width / 2, height / 2);
      const [rimX, rimY] = rimPoint(state.spot, width / 2, height / 2, r);
      const pull = 1 - Math.min(0.35 * (height / 2), Math.hypot(rimX, rimY)) / Math.max(Math.hypot(rimX, rimY), 0.0001);

      gl.uniform1f(uniforms.uSpot, state.spot);
      gl.uniform2f(uniforms.uEntry, rimX * pull * scaleX, rimY * pull * scaleY);
      gl.uniform3fv(uniforms.uLineColor, toRgb(s.lineColor));
      gl.uniform3fv(uniforms.uBaseColor, toRgb(s.baseColor));
      gl.uniform1f(uniforms.uIntensity, s.intensity * (state.level + state.press * 0.8));
      gl.uniform2f(uniforms.uWindow, s.shineSize / 360 + state.press * 0.06, s.shineFade / 360 + 0.0001);
      gl.uniform1f(uniforms.uThickness, s.thickness);
      gl.uniform1f(uniforms.uGlow, s.glow);

      gl.bindVertexArray(vao);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.bindVertexArray(null);
    };

    const frame = now => {
      raf = 0;
      if (!visible) return;
      const s = config;
      const dt = last ? Math.min(0.05, (now - last) / 1000) : 1 / 60;
      last = now;

      const target = aim(s);
      const spinning = s.autoAnimate && !reduceMotion;
      const steering = !!target && target.near > 0;

      if (!state.ready) {
        state.spot = restSpot(s);
        state.level = s.autoAnimate ? 1 : s.idleIntensity;
        state.ready = true;
      }

      let diff = 0;
      if (spinning && !steering) {
        state.spot = wrap(state.spot + (s.speed / TAU) * dt);
      } else {
        diff = (steering ? target.spot : restSpot(s)) - state.spot;
        diff -= Math.round(diff);
        // Exponential smoothing for butter-smooth gliding along the rounded border
        state.spot = wrap(state.spot + diff * (1 - Math.exp(-dt * 9)));
      }

      const targetLevel = s.autoAnimate ? 1 : s.idleIntensity + (1 - s.idleIntensity) * (target ? target.near : 0);
      state.level += (targetLevel - state.level) * (1 - Math.exp(-dt * 8));
      state.press *= Math.exp(-dt * 6);

      draw(s);

      const settling = Math.abs(diff) > 0.0002 || Math.abs(targetLevel - state.level) > 0.001 || state.press > 0.002;
      if (settling || (spinning && !steering)) {
        raf = requestAnimationFrame(frame);
      } else {
        last = 0;
      }
    };

    const wake = () => {
      rectStale = true;
      if (!raf && visible) raf = requestAnimationFrame(frame);
    };

    const measure = entry => {
      rectStale = true;
      const box = entry?.borderBoxSize?.[0];
      view.width = Math.max(1, box ? box.inlineSize : button.offsetWidth);
      view.height = Math.max(1, box ? box.blockSize : button.offsetHeight);
      view.ratio = Math.min(window.devicePixelRatio || 1, 3);
      canvas.width = Math.max(1, Math.round((view.width + PAD * 2) * view.ratio));
      canvas.height = Math.max(1, Math.round((view.height + PAD * 2) * view.ratio));
      if (state.ready) draw(config);
      wake();
    };

    const onPointerDown = () => {
      if (!config.disabled) state.press = 1;
      wake();
    };

    const resizeObserver = new ResizeObserver(entries => measure(entries[entries.length - 1]));
    resizeObserver.observe(button);

    const intersection = new IntersectionObserver(entries => {
      visible = entries.some(entry => entry.isIntersecting);
      if (visible) {
        last = 0;
        rectStale = true;
        wake();
      }
    });
    intersection.observe(button);

    globalPointer.listeners.add(wake);
    window.addEventListener('scroll', () => { rectStale = true; wake(); }, { passive: true });
    button.addEventListener('pointerdown', onPointerDown);

    measure();
    button._specularAttached = true;
    button._specularWake = wake;

    return button;
  }

  // Initialize specifically configured buttons
  function initHeaderButtons() {
    const pdfBtn = document.getElementById('btn-top-pdf');
    if (pdfBtn && !pdfBtn._specularAttached) {
      pdfBtn.classList.add('specular-btn-pdf');
      attachSpecularButton(pdfBtn, {
        radius: 6,
        lineColor: '#ffffff',
        baseColor: '#e5202e',
        intensity: 1.35,
        idleIntensity: 0.35,
        shineSize: 18,
        shineFade: 42,
        thickness: 1.4,
        glow: 1.35,
        speed: 0.35,
        proximity: 280,
        autoAnimate: false
      });
    }

    const emailBtn = document.getElementById('btn-email-modal-toggle');
    if (emailBtn && !emailBtn._specularAttached) {
      emailBtn.classList.add('specular-btn-email');
      attachSpecularButton(emailBtn, {
        radius: 6,
        lineColor: '#fff5d6',
        baseColor: '#fbbf24',
        intensity: 1.25,
        idleIntensity: 0.32,
        shineSize: 16,
        shineFade: 38,
        thickness: 1.3,
        glow: 1.25,
        speed: 0.35,
        proximity: 280,
        autoAnimate: false
      });
    }

    const fedBtn = document.getElementById('btn-fed-modal-toggle');
    if (fedBtn && !fedBtn._specularAttached) {
      fedBtn.classList.add('specular-btn-federation');
      attachSpecularButton(fedBtn, {
        radius: 6,
        lineColor: '#fff5d6',
        baseColor: '#fbbf24',
        intensity: 1.25,
        idleIntensity: 0.32,
        shineSize: 16,
        shineFade: 38,
        thickness: 1.3,
        glow: 1.25,
        speed: 0.35,
        proximity: 280,
        autoAnimate: false
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHeaderButtons);
  } else {
    initHeaderButtons();
  }

  // Expose global API
  window.SpecularButton = {
    attach: attachSpecularButton,
    initHeaders: initHeaderButtons
  };
})();
