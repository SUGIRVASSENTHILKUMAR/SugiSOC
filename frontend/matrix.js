/* Lightweight, decorative digital rain. No network calls or data access. */
(() => {
  'use strict';
  const canvas = document.getElementById('matrix-rain');
  if (!canvas || !canvas.getContext) return;
  const context = canvas.getContext('2d', { alpha: true });
  if (!context) return;
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const glyphs = '01ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let positions = [], width = 0, height = 0, raf = 0, last = 0;
  const fontSize = 16;
  const interval = 60; // ~16 frames / second; less work on laptops
  function resize() {
    const bounds = canvas.getBoundingClientRect();
    const scale = Math.min(window.devicePixelRatio || 1, 1.5);
    width = Math.max(1, Math.round(bounds.width));
    height = Math.max(1, Math.round(bounds.height));
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    context.setTransform(scale, 0, 0, scale, 0, 0);
    positions = Array.from({ length: Math.ceil(width / fontSize) }, () => Math.random() * -height / fontSize);
    context.clearRect(0, 0, width, height);
  }
  function draw(time) {
    raf = requestAnimationFrame(draw);
    if (time - last < interval) return;
    last = time;
    context.fillStyle = 'rgba(2, 5, 3, .20)';
    context.fillRect(0, 0, width, height);
    context.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, monospace`;
    for (let i = 0; i < positions.length; i++) {
      if (Math.random() > .55) continue; // sparse rain, not wallpaper
      const y = positions[i] * fontSize;
      context.fillStyle = Math.random() > .93 ? '#b8ffca' : '#00a82a';
      context.fillText(glyphs[(Math.random() * glyphs.length) | 0], i * fontSize, y);
      positions[i] += .55;
      if (y > height && Math.random() > .965) positions[i] = Math.random() * -18;
    }
  }
  function stop() { cancelAnimationFrame(raf); raf = 0; context.clearRect(0, 0, width, height); }
  function refresh() {
    stop();
    if (motion.matches || document.hidden) return;
    resize();
    raf = requestAnimationFrame(draw);
  }
  window.addEventListener('resize', refresh, { passive: true });
  document.addEventListener('visibilitychange', refresh);
  if (motion.addEventListener) motion.addEventListener('change', refresh);
  else motion.addListener(refresh);
  refresh();
})();
