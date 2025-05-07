var xkPresets =
    {
	"defined_presets": [
	    "APPLEID",  "DEFAULT",  "NTLM",  "SECURITYQ",  "WEB16",  "WEB32",  "WIFI",  "XKCD"
	],
	"preset_descriptions": {
	    "APPLEID": "A preset respecting the many prerequisites Apple places on Apple ID passwords. The preset also limits itself to symbols found on the iOS letter and number keyboards (i.e. not the awkward to reach symbol keyboard)",
	    "DEFAULT": "The default preset resulting in a password consisting of 3 random words of between 4 and 8 letters with alternating case separated by a random character, with two random digits before and after, and padded with two random characters front and back",
	    "NTLM": "A preset for 14 character Windows NTLMv1 password. WARNING - only use this preset if you have to, it is too short to be acceptably secure and will always generate entropy warnings for the case where the config and dictionary are known.",
	    "SECURITYQ": "A preset for creating fake answers to security questions.",
	    "WEB16": "A preset for websites that insit passwords not be longer than 16 characters. WARNING - only use this preset if you have to, it is too short to be acceptably secure and will always generate entropy warnings for the case where the config and dictionary are known.",
	    "WEB32": "A preset for websites that allow passwords up to 32 characteres long.",
	    "WIFI": "A preset for generating 63 character long WPA2 keys (most routers allow 64 characters, but some only 63, hence the odd length).",
	    "XKCD": "A preset for generating passwords similar to the example in the original XKCD cartoon, but with an extra word, a dash to separate the random words, and the capitalisation randomised to add sufficient entropy to avoid warnings."
	},
	// Crypt::HSXKPasswd(3) -> PRESETS
	"presets": {
	    "APPLEID": {
		"allow_accents": 0,
		"case_transform": "RANDOM",
		"num_words": 3,
		"padding_alphabet": [
		    "-", ":", ".", "!", "?", "@", "&"
		],
		"padding_character": "RANDOM",
		"padding_characters_after": 1,
		"padding_characters_before": 1,
		"padding_digits_after": 2,
		"padding_digits_before": 2,
		"padding_type": "FIXED",
		"separator_alphabet": [
		    "-", ":", ".", "@", ",", " "
		],
		"separator_character": "RANDOM",
		"word_length_max": 7,
		"word_length_min": 4
	    },
	    "DEFAULT": {
		"allow_accents": 0,
		"case_transform": "ALTERNATE",
		"num_words": 3,
		"padding_character": "RANDOM",
		"padding_characters_after": 2,
		"padding_characters_before": 2,
		"padding_digits_after": 2,
		"padding_digits_before": 2,
		"padding_type": "FIXED",
		"separator_character": "RANDOM",
		"symbol_alphabet": [
		    "!", "@", "$", "%", "^", "&", "*", "-", "_", "+", "=", ":", "|", "~", "?", "/", ".", ";"
		],
		"word_length_max": 8,
		"word_length_min": 4
	    },
	    "NTLM": {
		"allow_accents": 0,
		"case_transform": "INVERT",
		"num_words": 2,
		"padding_alphabet": [
		    "!", "@", "$", "%", "^", "&", "*", "+", "=", ":", "|", "~", "?"
		],
		"padding_character": "RANDOM",
		"padding_characters_after": 1,
		"padding_characters_before": 0,
		"padding_digits_after": 0,
		"padding_digits_before": 1,
		"padding_type": "FIXED",
		"separator_alphabet": [
		    "-", "+", "=", ".", "*", "_", "|", "~", ","
		],
		"separator_character": "RANDOM",
		"word_length_max": 5,
		"word_length_min": 5
	    },
	    "SECURITYQ": {
		"allow_accents": 0,
		"case_transform": "NONE",
		"num_words": 6,
		"padding_alphabet": [ ".", "!", "?" ],
		"padding_character": "RANDOM",
		"padding_characters_after": 1,
		"padding_characters_before": 0,
		"padding_digits_after": 0,
		"padding_digits_before": 0,
		"padding_type": "FIXED",
		"separator_character": " ",
		"word_length_max": 8,
		"word_length_min": 4
	    },
	    "WEB16": {
		"allow_accents": 0,
		"case_transform": "RANDOM",
		"num_words": 3,
		"padding_digits_after": 2,
		"padding_digits_before": 0,
		"padding_type": "NONE",
		"separator_character": "RANDOM",
		"symbol_alphabet": [
		    "!", "@", "$", "%", "^", "&", "*", "-", "_", "+", "=", ":", "|", "~", "?", "/", ".", ";"
		],
		"word_length_max": 4,
		"word_length_min": 4
	    },
	    "WEB32": {
		"allow_accents": 0,
		"case_transform": "ALTERNATE",
		"num_words": 4,
		"padding_alphabet": [
		    "!", "@", "$", "%", "^", "&", "*", "+", "=", ":", "|", "~", "?"
		],
		"padding_character": "RANDOM",
		"padding_characters_after": 1,
		"padding_characters_before": 1,
		"padding_digits_after": 2,
		"padding_digits_before": 2,
		"padding_type": "FIXED",
		"separator_alphabet": [
		    "-", "+", "=", ".", "*", "_", "|", "~", ","
		],
		"separator_character": "RANDOM",
		"word_length_max": 5,
		"word_length_min": 4
	    },
	    "WIFI": {
		"allow_accents": 0,
		"case_transform": "RANDOM",
		"num_words": 6,
		"pad_to_length": 63,
		"padding_alphabet": [
		    "!", "@", "$", "%", "^", "&", "*", "+", "=", ":", "|", "~", "?"
		],
		"padding_character": "RANDOM",
		"padding_digits_after": 4,
		"padding_digits_before": 4,
		"padding_type": "ADAPTIVE",
		"separator_alphabet": [
		    "-", "+", "=", ".", "*", "_", "|", "~", ","
		],
		"separator_character": "RANDOM",
		"word_length_max": 8,
		"word_length_min": 4
	    },
	    "XKCD": {
		"allow_accents": 0,
		"case_transform": "RANDOM",
		"num_words": 5,
		"padding_digits_after": 0,
		"padding_digits_before": 0,
		"padding_type": "NONE",
		"separator_character": "-",
		"word_length_max": 8,
		"word_length_min": 4
	    }
	}
    };
var onPost    = "";

///////////////////////////////////////////////////////////////
// prefix is a class prefix like alg-, sep-, etc defined in
// templates/protected/tool/pwdgen-create.html.ep
///////////////////////////////////////////////////////////////

function updateClassWithPrefix($node, prefix, newClass) {
  $node
    .removeClass(function(_index, classNames) {
      // split on whitespace, keep only those starting with prefix, join back
      return classNames
	.split(/\s+/)
	.filter(function(c) { return c.indexOf(prefix) === 0; })
	.join(' ');
    })
    .addClass(newClass);
}

function loadPreset(presets, presetName) {
    console.log('onPost: →'+onPost+'←');
    var preset;
    if ( onPost == '' ) {
	preset = presets.presets[presetName];
    } else {
	preset = onPost;
	onPost = '';
    }
    const descr  = presets.preset_descriptions[presetName];
    if ( descr ) $('#pwd_algHelpBlock').html(descr);
    if ( ! preset ) return;
    // console.log(preset);
    Object.keys(preset).forEach(function (key) {
	if ( key == 'separator_character' && preset[key].length == 1 ) { // CHAR
	    $('#xk_'+key).val('sep-char').change();
	    $('#xk_'+key+'_char').val(preset[key]);

	} else if ( key == 'separator_character' && preset[key] == 'RANDOM' ) {
	    $('#xk_'+key).val('sep-'+preset[key].toLowerCase()).change();
	    if ( 'separator_alphabet' in preset ) {
		$('#xk_separator_alphabet').val(preset.separator_alphabet.join(''));
	    }

	} else if ( key == 'separator_character' && preset[key] == 'NONE' ) {
	    $('#xk_'+key).val('sep-'+preset[key].toLowerCase()).change();

	} else if ( key == 'padding_type' ) {
	    $('#xk_'+key).val('pad-'+preset[key].toLowerCase()).change();

	} else if ( key == 'padding_character' ) {
	    $('#xk_'+key).val('pch-'+preset[key].toLowerCase()).change();

	    $('#xk_padding_alphabet').val( 'padding_alphabet' in preset ? preset.padding_alphabet.join('') : presets.presets['DEFAULT'].symbol_alphabet.join('') );

	} else {
	    $('#xk_'+key).val(preset[key]);
	}
    });
}

/////////////////////////////////////////////////////////////////////////////////
// password ALG selection
/////////////////////////////////////////////////////////////////////////////////
$('#pwd_operations').on('change', 'select[id=pwd_alg]', function(e) {
  var $container = $(this).closest('.target-container');
    var value = $(this).val().toLowerCase().slice(4);
  if ( xkPresets ) {
    loadPreset(xkPresets, value.toUpperCase());
    // should be here, since #xk_separator_character_char is set not from form but via JS
    $('#xk_separator_character_char').change();
  }
   updateClassWithPrefix($container, 'alg-', value ? value : 'alg-none');
} ).change();


/////////////////////////////////////////////////////////////////////////////////
// SEPARATOR section
/////////////////////////////////////////////////////////////////////////////////
$('#sep').on('change', '#xk_separator_character', function(e) {
    var $container = $(this).closest('.target-container');
    var value = $(this).val().toLowerCase();
    updateClassWithPrefix($container, 'sep-', value ? value : 'sep-none');
} ).change();
/////////////////////////////////////////////////////////////////////////////////
// Here we want <small> inside a new sibling <div>, not inside the parent div. //
/////////////////////////////////////////////////////////////////////////////////
const parentDiv = $('#xk_separator_character_char').parent();
const newDiv = $('<div>', {              // Create a new div with the same classes
  class: parentDiv.attr('class')         // copy the same classes
});
$('#sepCharHelpBlock').appendTo(newDiv); // Move the <small> element into the new div
newDiv.insertAfter(parentDiv);           // Insert it after #xk_separator_character_char

$('#xk_separator_character_char').on('input', function() {
  const val = this.value;
  if (!val) {
    $('#sepCharHelpBlock').html('');
    return;
  }
  const code = val.charCodeAt(0);
  const charType = code < 255 ? 'ASCII' : 'char';
  const toOutput = `${charType}: ${code}`;
  console.log(`CHARACTER "${val}" is: ${toOutput}`);
  $('#sepCharHelpBlock').html(toOutput);
});


/////////////////////////////////////////////////////////////////////////////////
// PADDING TYPE
/////////////////////////////////////////////////////////////////////////////////
$('#padd').on('change', '#xk_padding_type', function(e) {
  var $container = $(this).closest('.target-container');
  var value = $(this).val().toLowerCase();
  updateClassWithPrefix($container, 'pad-', value ? value : 'pad-none');
} ).change();


/////////////////////////////////////////////////////////////////////////////////
// PADDING CHARACTER
/////////////////////////////////////////////////////////////////////////////////
$('#pch').on('change', '#xk_padding_character', function(e) {
    console.log('#pad-char');
  var $container = $(this).closest('.target-container');
  var value = $(this).val().toLowerCase();
  updateClassWithPrefix($container, 'pch-', value ? value : 'pch-none');
} ).change();


$('#pwd_alg').change();
$('#xk_padding_type').change();
$('#xk_separator_character').change();
$('#xk_padding_character').change();
