export const sample = [
  { path: 'browser.tsx', content: '// Synthetic fixture. Do not execute.\nfunction preview() {\n  const input: string = new URLSearchParams(location.search).get("q") ?? "";\n  const html = "<p>" + input + "</p>";\n  document.querySelector("#preview")!.innerHTML = html;\n  document.querySelector("#safe")!.textContent = input;\n  window.open(input);\n  return <section dangerouslySetInnerHTML={{ __html: input }} />;\n}\n' },
  { path: 'controls.js', content: '// A constant assignment clears the tracked input.\nlet value = location.hash;\nvalue = "A fixed message";\noutput.innerHTML = value;\n\n// HTML sanitizer: still requires human verification.\nconst raw = location.search;\noutput.innerHTML = DOMPurify.sanitize(raw);\n\n// Text output is not an HTML-write sink.\noutput.textContent = raw;\n' }
];
export const componentSample = [
  {path:'components/Preview.vue', content:'<template>\n  <section>Template expressions are outside this analyzer.</section>\n</template>\n<script setup lang="ts">\nconst query: string = location.hash;\nconst html = "<p>" + query + "</p>";\ndocument.querySelector("#preview")!.innerHTML = html;\n</script>\n'},
  {path:'pages/preview.svelte', content:'<script lang="ts">\nconst input: string = location.search;\nconst clean = DOMPurify.sanitize(input);\npreview.innerHTML = clean;\n</script>\n<p>Framework rendering is not modeled.</p>\n'},
  {path:'index.html', content:'<!doctype html>\n<title>Inert synthetic fixture</title>\n<script type="application/json">{"html":"not code"}</script>\n<script>\nconst q = location.hash;\noutput.textContent = q;\n</script>\n<script src="./external.js"></script>\n'}
];
