// IDEA: https://bootsnipp.com/snippets/featured/dynamic-form-fields-add-amp-remove-bs3

$(document).ready(function() {
  $('#modify-tt-form').on('click', '.btn-add', function(e) {
    e.preventDefault();
    console.log('btn-add was clicked');
    
    var controlForm = $(this).closest('.controls'),
	currentEntry = controlForm.find(".entry").last(),
	newEntry = $(currentEntry.clone()).appendTo(controlForm);
    //debugger;

    newEntry.find('.form-control').val('');
    controlForm.find('.entry:not(:last) .btn-add')
      .removeClass('btn-add').addClass('btn-erase')
      .html('<span class="fa-regular fa-fw fa-trash-can"></span>');
    return false;
  }).on('click', '.btn-erase', function(e)
	{
	  e.preventDefault();
	  console.log('btn-erase was clicked');

     	  $(this).closest('.input-group').find('.form-control').val('');
	  return false;
	});

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
