/*!
 * common things
 */

/**
 * Copies the rendered inner text of a targeted DOM element to the user's clipboard.
 *
 * Creates a hidden `<textarea>` fallback to execute `document.execCommand('copy')`.
 * If the element does not exist, the operation exits silently.
 *
 * @param {string} selector - A valid CSS selector string matching the source element.
 * @returns {void}
 *
 * @example
 * copyToClipboard('#myElement');
 */
function copyToClipboard(selector) {
  const element = document.querySelector(selector);
  if (!element) return;

  // Ensure we're copying rendered multiline text
  const text = element.innerText;
  console.log('→' + text + '←');

  // Use a temporary <textarea> for clipboard operation
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'absolute';
  textarea.style.left = '-9999px';

  document.body.appendChild(textarea);
  textarea.select();

  try {
    document.execCommand('copy');
    console.log('Copied successfully');
  } catch (err) {
    console.error('Copy failed', err);
  }

  document.body.removeChild(textarea);
}

/**
 * Triggers an immediate browser file download from an in-memory string.
 *
 * Generates an object URL backed by a `Blob`, programmatically clicks a hidden anchor
 * element, and schedules the cleanup of the object URL after 1.5 seconds.
 *
 * @param {string} text - The raw string data to include in the downloaded file.
 * @param {string} fileType - The MIME type of the file (e.g., `'text/plain'`, `'application/json'`).
 * @param {string} fileName - The default file name presented in the browser save prompt.
 * @returns {void}
 *
 * @example
 * onclick="downloadString(
 *   document.querySelector('#ssh_private').innerText,
 *   'text/plain',
 *   'ssh-key.pvt'
 * )""
 */
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

/**
 * Persists and restores the expanded or collapsed state of a Bootstrap collapsible
 * element across page reloads using `localStorage`.
 *
 * Attaches listeners for Bootstrap's `shown.bs.collapse` and `hidden.bs.collapse` events
 * to save state under `localStorage['<elementId>State']`. On `DOMContentLoaded`, it reads
 * the stored value and adds or removes the `'show'` class accordingly (defaulting to expanded).
 *
 * @param {string} elementId - The DOM `id` attribute of the collapsible element to observe.
 * @returns {void}
 *
 * @example
 * // Track left sidebar collapse state
 * manageCollapseState('sidebar-left');
 *
 * @example
 * // Track an aside panel
 * manageCollapseState('aside');
 */
function manageCollapseState(elementId) {
   var sidebarElement = document.getElementById(elementId);

    // Function to set the initial state based on local storage
    function setInitialState() {
	const savedState = localStorage.getItem(elementId + 'State');
	if (savedState === 'collapsed') {
	    sidebarElement.classList.remove('show');  // Ensure it's collapsed
	} else {
	    sidebarElement.classList.add('show');  // Ensure it's expanded
	}
    }

    // Apply the stored state when the document is ready
    document.addEventListener('DOMContentLoaded', function () {
	setInitialState();
    });

    // Listen for the collapse event to save the current state
    sidebarElement.addEventListener('hidden.bs.collapse', function () {
	localStorage.setItem(elementId + 'State', 'collapsed');
    });

    sidebarElement.addEventListener('shown.bs.collapse', function () {
	localStorage.setItem(elementId + 'State', 'expanded');
    });
}

// Call the function with the ID of the element you want to track
manageCollapseState('sidebar-left');

// If you want to track another element (e.g., an aside)
manageCollapseState('aside');

/**
 * Generates a zero-padded timestamp string: YYYYMMDD_HHmmss
 * @returns {string}
 */
function getTimestamp() {
  const now = new Date();
  const pad = (num) => String(num).padStart(2, '0');

  const year = now.getFullYear();
  const month = pad(now.getMonth() + 1);
  const day = pad(now.getDate());
  const hours = pad(now.getHours());
  const minutes = pad(now.getMinutes());
  const seconds = pad(now.getSeconds());

  return `${year}${month}${day}_${hours}${minutes}${seconds}`;
}

/**
  * Delegated click event listener for async URL actions.
  *
  * Intercepts clicks on elements matching `.js-btn-copy-url` or `.js-btn-save-url`,
  * fetches plain text from the endpoint defined in `data-fetch-url`, and either:
  * - Copies the payload to the system clipboard.
  * - Prompts a file download using the name from `data-filename` (or a fallback timestamp).
  *
  * @listens Document#click
  * @param {MouseEvent} e - The native DOM click event.
  * @returns {Promise<void>}
  */
document.addEventListener('click', async function (e) {
  /** @type {HTMLButtonElement|null} */
  const copyBtn = e.target.closest('.js-btn-copy-url');

  /** @type {HTMLButtonElement|null} */
  const saveBtn = e.target.closest('.js-btn-save-url');

  if (!copyBtn && !saveBtn) return;
  e.preventDefault();

  /** @type {HTMLButtonElement} */
  const btn = copyBtn || saveBtn;

  /** @type {string|undefined} */
  const url = btn.dataset.fetchUrl;
  if (!url) return;

  try {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    const text = await res.text();

    if (copyBtn) {
      // Use Modern Clipboard API with fallback for older browsers / non-HTTPS
      if (navigator.clipboard && window.isSecureContext) {
	await navigator.clipboard.writeText(text);
      } else {
	const temp = document.createElement('textarea');
	temp.value = text;
	document.body.appendChild(temp);
	temp.select();
	document.execCommand('copy');
	document.body.removeChild(temp);
      }
      alert('Copied to clipboard');
    }

    if (saveBtn) {
      const defaultFilename = `searchresult-${getTimestamp()}.ldif`;
      const filename = btn.dataset.filename || defaultFilename;

      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    }
  } catch (err) {
    /** @type {Error} */
    const error = err instanceof Error ? err : new Error(String(err));
    alert((copyBtn ? 'Copy' : 'Download') + ' failed: ' + error.message);
  }
});
