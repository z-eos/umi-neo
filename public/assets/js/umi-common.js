/*! 
 * common things
 */

// onclick="copyToClipboard('#ssh_private')"
function copyToClipboard(selector) {
  var range = document.createRange();
  range.selectNode(document.querySelector(selector));
  window.getSelection().removeAllRanges(); // clear current selection
  window.getSelection().addRange(range);   // to select text
  document.execCommand("copy");
  window.getSelection().removeAllRanges(); // to deselect
}

// onclick="downloadString(document.querySelector('#ssh_private').innerText, 'text/plain', 'ssh-key.pvt')"
function downloadString(text, fileType, fileName) {
  var blob = new Blob([text], { type: fileType });
  var a = document.createElement('a');
  a.download = fileName;
  a.href = URL.createObjectURL(blob);
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function() { URL.revokeObjectURL(a.href); }, 1500);
}

