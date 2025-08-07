$(document).ready(function() {

    // Function to clone input fields
    function cloneField() {
	const $inputGroup = $(this).closest('.entry-removable');
	const $newInputGroup = $inputGroup.clone();

	// Clear the value of the cloned input and textarea fields
	$newInputGroup.find('input, textarea').val('');

	// Make the "Add" button in the cloned input group invisible
	$newInputGroup.find('.btn-add').addClass('invisible');

	// Append the cloned input group after the original
	$inputGroup.after($newInputGroup);
    }

    function deleteField() {
	const $inputGroup = $(this).closest('.entry-at-least-one, .entry-removable');
	const $container = $inputGroup.parent();

	if ($inputGroup.hasClass('entry-removable')) {
	    $inputGroup.remove();
	} else if ($inputGroup.hasClass('entry-at-least-one')) {
	    if ($container.find('.entry-at-least-one').length > 1) {
		$inputGroup.remove();
	    }
	}
    }

    // Attach event listeners to the initial buttons
    $(document).on('click', '.btn-add', cloneField);
    $(document).on('click', '.btn-delete', deleteField);

    $("#attr_unused").on("change", function(e) {
	var $this = $(this),
	    value = $this.val();

	if (!value || !value.length) return;
	var $form = $this.parents("form");
	$form.find("div.attr-unused")
	    .addClass("hidden")
	    .each(function(index, item) {
		$(item).find("input:text, input:password, input:file, select, textarea, input:radio, input:checkbox")
		    .each(function(id, element) {
			$(element).removeAttr('checked')
			    .removeAttr('selected')
			    .children("option")
			    .first()
			    .prop("selected",true);
		    }).val('');
	    });
	$form.find("div#"+value).removeClass("d-none");
    });

});
