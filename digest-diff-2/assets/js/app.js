// Same theme/palette conventions as clavium, dominium and lastmile; no inline scripts.
(() => {
  const root=document.documentElement;
  const palettes=['neutral','blue','green','orange','violet'];
  const cookie=(name,value)=>document.cookie=`${name}=${value}; path=/; max-age=31536000; samesite=lax`;
  if(!document.cookie.includes('digest_diff_theme=')&&matchMedia('(prefers-color-scheme: dark)').matches)root.classList.add('dark');
  document.addEventListener('click',event=>{
    if(event.target.closest('[data-theme-toggle]'))cookie('digest_diff_theme',root.classList.toggle('dark')?'dark':'light');
    const menu=document.querySelector('.theme-menu');
    if(menu&&!menu.contains(event.target))menu.open=false;
  });
  document.addEventListener('change',event=>{
    if(event.target.matches('[data-appearance-select]')&&['minimal','accent','full'].includes(event.target.value)){
      root.dataset.appearance=event.target.value;cookie('digest_diff_appearance',event.target.value);
    }
    if(event.target.matches('[data-palette-select]')&&palettes.includes(event.target.value)){
      root.dataset.palette=event.target.value;cookie('digest_diff_palette',event.target.value);
      if(root.dataset.appearance==='minimal'){
        root.dataset.appearance='accent';cookie('digest_diff_appearance','accent');
        document.querySelector('[data-appearance-select]').value='accent';
      }
    }
  });
  document.addEventListener('keydown',event=>{if(event.key==='Escape'){const menu=document.querySelector('.theme-menu');if(menu?.open){menu.open=false;menu.querySelector('summary').focus();}}});
  document.addEventListener('keydown',event=>{if((event.metaKey||event.ctrlKey)&&event.key==='k'){const field=document.querySelector('[data-search]');if(field){event.preventDefault();field.focus();}}});
  document.addEventListener('htmx:sendError',()=>{document.getElementById('connection-notice').hidden=false;});
  document.addEventListener('htmx:afterRequest',event=>{if(event.detail.successful)document.getElementById('connection-notice').hidden=true;});
})();
