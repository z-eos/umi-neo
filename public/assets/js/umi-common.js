/*!
 * common things
 */

// const FORM_SELECTOR = '.injectable-form';
// const CONTAINER_SELECTOR = '#workingfield';

// $(document).on('submit', FORM_SELECTOR, async function(event) {
//   event.preventDefault();  // Prevent default form submission and page refresh

//   const url = $(this).attr('action');  // Get form action URL
//   const formData = $(this).serialize();  // Serialize the form data

//   try {
//     const response = await fetch(url, {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/x-www-form-urlencoded'  // Indicate form submission
//       },
//       body: formData  // Send serialized form data
//     });

//     if (!response.ok) {
//       throw new Error('Server error');
//     }

//     const html = await response.text();  // Get response HTML
//     $(CONTAINER_SELECTOR).html(html);  // Inject response HTML into #workingfield
//   } catch (e) {
//     alert('Something went wrong: ' + e.message);  // Error handling
//   }
// });



// copyToClipboard('#myElement');
function copyToClipboard(selector) {
  const element = document.querySelector(selector);
  if (!element) return;

  // Ensure we're copying rendered multiline text
  const text = element.innerText;
  console.log('→'+text+'←');

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
