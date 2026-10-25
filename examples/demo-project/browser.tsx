// Synthetic training fixture. Do not deploy these deliberately risky patterns.
function previewExample() {
  const text: string = new URLSearchParams(window.location.search).get("q") ?? "";
  const html = "<p>" + text + "</p>";
  document.querySelector("#unsafe-preview")!.innerHTML = html;
  window.open(text);
  const view = <section dangerouslySetInnerHTML={{ __html: text }} />;
  // Safe text output: should not produce an AST HTML-write finding.
  document.querySelector("#safe-preview")!.textContent = text;
  return view;
}
