document.addEventListener('DOMContentLoaded', function() {
    const choicesConfig = {
	addItems: true,
	allowHTML: true,
	createItem: true,
	fuseOptions: {
	    threshold: 0.24,
	    includeScore: true,
	    ignoreDiacritics: true,
	    ignoreLocation: true
	},
	placeholder: true,
	placeholderValue: 'Pick member/s',
	removeItemButton: true,
	removeItemIconText: '×',
	renderChoiceLimit: -1,
	searchResultLimit: -1,
    };

    // Initialize Choices.js on every <select> element on the page.
    document.querySelectorAll('select').forEach(function(selectElement) {
	new Choices(selectElement, choicesConfig);
    });
});
