/**
 * DotField Interactive Grid Matrix Background
 */
(function() {
  const TWO_PI = Math.PI * 2;

  function initDotField(container, options = {}) {
    if (!container) return null;

    const defaults = {
      dotRadius: 1.8,
      dotSpacing: 16,
      cursorRadius: 380,
      cursorForce: 0.1,
      bulgeOnly: true,
      bulgeStrength: 75,
      glowRadius: 220,
      sparkle: true,
      waveAmplitude: 0.6,
      gradientFrom: 'rgba(229, 34, 47, 0.45)', // HoneyTrack cyber red
      gradientTo: 'rgba(107, 127, 168, 0.35)',   // HoneyTrack tactical blue
      glowColor: '#e5222f'
    };

    const p = { ...defaults, ...options };
    const glowId = 'dot-field-glow-' + Math.random().toString(36).slice(2, 9);

    // Setup DOM
    container.classList.add('dot-field-container');
    container.innerHTML = `
      <canvas style="position:absolute;inset:0;width:100%;height:100%;"></canvas>
      <svg style="position:absolute;inset:0;width:100%;height:100%;pointer-events:none;">
        <defs>
          <radialGradient id="${glowId}">
            <stop offset="0%" stop-color="${p.glowColor}" stop-opacity="0.22" />
            <stop offset="60%" stop-color="${p.glowColor}" stop-opacity="0.06" />
            <stop offset="100%" stop-color="transparent" stop-opacity="0" />
          </radialGradient>
        </defs>
        <circle id="${glowId}-circle" cx="-9999" cy="-9999" r="${p.glowRadius}" fill="url(#${glowId})" style="opacity: 0; will-change: opacity, cx, cy;" />
      </svg>
    `;

    const canvas = container.querySelector('canvas');
    const glowEl = container.querySelector(`#${glowId}-circle`);
    if (!canvas) return null;
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return null;

    let dots = [];
    let mouse = { x: -9999, y: -9999, prevX: -9999, prevY: -9999, speed: 0 };
    let size = { w: 0, h: 0, offsetX: 0, offsetY: 0 };
    let glowOpacity = 0;
    let engagement = 0;
    let frameCount = 0;
    let rafId = null;
    let dpr = 1;
    let resizeTimer = null;

    function buildDots(w, h) {
      const step = p.dotRadius + p.dotSpacing;
      const cols = Math.floor(w / step);
      const rows = Math.floor(h / step);
      const padX = (w % step) / 2;
      const padY = (h % step) / 2;
      const total = rows * cols;
      const newDots = new Array(total);
      let idx = 0;

      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          const ax = padX + col * step + step / 2;
          const ay = padY + row * step + step / 2;
          newDots[idx++] = { ax, ay, sx: ax, sy: ay, vx: 0, vy: 0, x: ax, y: ay };
        }
      }
      dots = newDots;
    }

    function doResize() {
      const rect = container.getBoundingClientRect();
      const w = rect.width || window.innerWidth;
      const h = rect.height || window.innerHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 2);

      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      size = {
        w,
        h,
        offsetX: rect.left + window.scrollX,
        offsetY: rect.top + window.scrollY,
      };

      buildDots(w, h);
    }

    function resize() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(doResize, 80);
    }

    function onMouseMove(e) {
      mouse.x = e.pageX - size.offsetX;
      mouse.y = e.pageY - size.offsetY;
    }

    function onTouchMove(e) {
      if (e.touches && e.touches[0]) {
        mouse.x = e.touches[0].pageX - size.offsetX;
        mouse.y = e.touches[0].pageY - size.offsetY;
      }
    }

    function updateMouseSpeed() {
      const dx = mouse.prevX - mouse.x;
      const dy = mouse.prevY - mouse.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      mouse.speed += (dist - mouse.speed) * 0.5;
      if (mouse.speed < 0.001) mouse.speed = 0;
      mouse.prevX = mouse.x;
      mouse.prevY = mouse.y;
    }

    const speedInterval = setInterval(updateMouseSpeed, 20);

    function tick() {
      frameCount++;
      const { w, h } = size;
      if (w <= 0 || h <= 0) {
        rafId = requestAnimationFrame(tick);
        return;
      }

      const len = dots.length;
      const t = frameCount * 0.02;

      const targetEngagement = Math.min(mouse.speed / 5, 1);
      engagement += (targetEngagement - engagement) * 0.06;
      if (engagement < 0.001) engagement = 0;
      const eng = engagement;

      glowOpacity += (eng - glowOpacity) * 0.08;

      if (glowEl) {
        glowEl.setAttribute('cx', mouse.x);
        glowEl.setAttribute('cy', mouse.y);
        glowEl.style.opacity = glowOpacity.toFixed(3);
      }

      ctx.clearRect(0, 0, w, h);

      const grad = ctx.createLinearGradient(0, 0, w, h);
      grad.addColorStop(0, p.gradientFrom);
      grad.addColorStop(1, p.gradientTo);
      ctx.fillStyle = grad;

      const cr = p.cursorRadius;
      const crSq = cr * cr;
      const rad = p.dotRadius / 2;
      const isBulge = p.bulgeOnly;

      ctx.beginPath();

      for (let i = 0; i < len; i++) {
        const d = dots[i];
        const dx = mouse.x - d.ax;
        const dy = mouse.y - d.ay;
        const distSq = dx * dx + dy * dy;

        if (distSq < crSq && eng > 0.01) {
          const dist = Math.sqrt(distSq);
          if (isBulge) {
            const ratio = 1 - dist / cr;
            const push = ratio * ratio * p.bulgeStrength * eng;
            const angle = Math.atan2(dy, dx);
            d.sx += (d.ax - Math.cos(angle) * push - d.sx) * 0.15;
            d.sy += (d.ay - Math.sin(angle) * push - d.sy) * 0.15;
          } else {
            const angle = Math.atan2(dy, dx);
            const move = (500 / dist) * (mouse.speed * p.cursorForce);
            d.vx += Math.cos(angle) * -move;
            d.vy += Math.sin(angle) * -move;
          }
        } else if (isBulge) {
          d.sx += (d.ax - d.sx) * 0.1;
          d.sy += (d.ay - d.sy) * 0.1;
        }

        if (!isBulge) {
          d.vx *= 0.9;
          d.vy *= 0.9;
          d.x = d.ax + d.vx;
          d.y = d.ay + d.vy;
          d.sx += (d.x - d.sx) * 0.1;
          d.sy += (d.y - d.sy) * 0.1;
        }

        let drawX = d.sx;
        let drawY = d.sy;
        if (p.waveAmplitude > 0) {
          drawY += Math.sin(d.ax * 0.03 + t) * p.waveAmplitude;
          drawX += Math.cos(d.ay * 0.03 + t * 0.7) * p.waveAmplitude * 0.5;
        }

        if (p.sparkle) {
          const hash = ((i * 2654435761) ^ (frameCount >> 3)) >>> 0;
          if ((hash % 100) < 3) {
            ctx.moveTo(drawX + rad * 1.8, drawY);
            ctx.arc(drawX, drawY, rad * 1.8, 0, TWO_PI);
          } else {
            ctx.moveTo(drawX + rad, drawY);
            ctx.arc(drawX, drawY, rad, 0, TWO_PI);
          }
        } else {
          ctx.moveTo(drawX + rad, drawY);
          ctx.arc(drawX, drawY, rad, 0, TWO_PI);
        }
      }

      ctx.fill();

      rafId = requestAnimationFrame(tick);
    }

    doResize();
    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('touchmove', onTouchMove, { passive: true });
    rafId = requestAnimationFrame(tick);

    return {
      destroy: () => {
        cancelAnimationFrame(rafId);
        clearInterval(speedInterval);
        clearTimeout(resizeTimer);
        window.removeEventListener('resize', resize);
        window.removeEventListener('mousemove', onMouseMove);
        window.removeEventListener('touchmove', onTouchMove);
        container.innerHTML = '';
      }
    };
  }

  // Auto-init on elements with #dot-field or [data-dot-field]
  if (typeof window !== 'undefined') {
    window.initDotField = initDotField;
    document.addEventListener('DOMContentLoaded', () => {
      const container = document.getElementById('dot-field') || document.querySelector('[data-dot-field]');
      if (container) initDotField(container);
    });
  }
})();
