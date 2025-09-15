// Lightweight animated gradient / particle-ish background
(function(){
  const overlay = document.querySelector('.bg-overlay');
  if(!overlay) return;
  let t = 0;
  function tick(){
    t += 0.0025; // slow
    const a = Math.sin(t) * 8 + 8;
    const b = Math.cos(t*0.75) * 6 + 8;
    overlay.style.background = `radial-gradient(${120+a}px ${80+b}px at 18% 20%, rgba(2,137,204,.25), transparent), radial-gradient(${100+b}px ${70+a}px at 82% 16%, rgba(2,22,63,.45), transparent), linear-gradient(135deg, rgba(2,22,63,.78), rgba(2,137,204,.35))`;
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();

