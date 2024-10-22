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

// Function to handle storing and applying the collapse state
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
