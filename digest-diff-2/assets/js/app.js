// Same theme/palette conventions as clavium, dominium and lastmile; no inline scripts.
(() => {
  const root=document.documentElement;
  const palettes=['neutral','blue','green','orange','violet'];
  const cookie=(name,value)=>document.cookie=`${name}=${value}; path=/; max-age=31536000; samesite=lax`;
  if(!document.cookie.includes('digest_diff_theme=')&&matchMedia('(prefers-color-scheme: dark)').matches)root.classList.add('dark');
  document.addEventListener('click',event=>{
    if(event.target.closest('[data-theme-toggle]'))cookie('digest_diff_theme',root.classList.toggle('dark')?'dark':'light');
    if(event.target.closest('[data-palette-cycle]')){root.dataset.palette=palettes[(palettes.indexOf(root.dataset.palette||'neutral')+1)%palettes.length];cookie('digest_diff_palette',root.dataset.palette);}
  });
  document.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key==='k'){const field=document.querySelector('[data-search]');if(field){event.preventDefault();field.focus();}}});
  document.addEventListener('htmx:sendError',()=>{document.getElementById('connection-notice').hidden=false;});
  document.addEventListener('htmx:afterRequest',event=>{if(event.detail.successful)document.getElementById('connection-notice').hidden=true;});
})();
