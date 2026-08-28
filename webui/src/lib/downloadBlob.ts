export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  // Firefox only starts the download for a link that is in the document; a
  // detached element's click() is a no-op there. Chrome tolerates a detached
  // link, so the previous inline versions worked in the smoke browser and hid
  // this on Firefox.
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  link.remove();
  // The browser reads the object URL asynchronously after click(); revoking it
  // in the same tick can cut the read short and produce an empty/failed file.
  // Defer the revoke so the download has the URL when it goes to read it.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
