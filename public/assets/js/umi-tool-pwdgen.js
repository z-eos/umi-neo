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
console.log('onPost: →'+onPost+'←');
function loadPreset(presets, presetName) {
    var preset;
    if ( onPost == '' ) {
        preset = presets.presets[presetName];
    } else {
        preset = onPost;
        onPost = '';
    }
    var descr  = presets.preset_descriptions[presetName];
    if ( descr ) $('#pwd_algHelpBlock').html(descr);
    if ( ! preset ) return;
    console.log(preset);
    Object.keys(preset).forEach(function (key) {
        if ( key == 'separator_character' && preset[key].length == 1 ) {
            $('#xk_'+key).val('CHAR');
            $('#xk_separator_character').change();
            var k = key+'_char';
            $('#xk_'+k).val(preset[key]);
        } else if ( key == 'separator_character' && preset[key] == 'RANDOM' ) {
            $('#xk_'+key).val('RANDOM');
            $('#xk_separator_character').change();
            var k = key+'_random';
            if ( 'separator_alphabet' in preset ) {
                $('#xk_'+k).val(preset.separator_alphabet.join(''));
            } else {
                $('#xk_'+k).val('');
            }
        } else if ( key == 'padding_type' ) {
            $('#xk_'+key).val(preset[key]);
            $('#xk_padding_type').change();
        } else if ( key == 'padding_character' ) {
            $('#xk_'+key).val(preset[key]);
            $('#xk_padding_character').change();
            var k = key+'_random';
            if ( 'padding_alphabet' in preset ) {
                $('#xk_'+k).val(preset.padding_alphabet.join(''));
            } else {
                $('#xk_'+k).val('');
            }
        } else {
            $('#xk_'+key).val(preset[key]);
        }
    });
}

$('#sepCharHelpBlock').appendTo( $('#xk_separator_character_char').parent() );
$('#xk_separator_character_char').change( function() {
  console.log('CHANGED ', this.value);
  var char = this.value.charCodeAt(0) < 255 ? 'ASCII' : 'char';
  $('#sepCharHelpBlock').html( $(this).val() ? +char+' code: '+this.value.charCodeAt(0) : '' );
});
// -------------------------------------------------------------------------
$('#pwd_operations').on('change', 'select[id=pwd_alg]', function(e) {
  var $container = $(this).closest('.target-container');
  var value = $(this).val().toLowerCase();
  if ( xkPresets ) {
    loadPreset(xkPresets, value.toUpperCase());
    // should be here, since #xk_separator_character_char is set not from form but via js
    $('#xk_separator_character_char').change();
  }
  $container.attr(
    'class', 'target-container ' + (value ? ' alg '+value : ' alg none'),
  );
} ).change();
// -------------------------------------------------------------------------
$('#padd').on('change', '#xk_padding_type', function(e) {
  var $container = $(this).closest('.target-container');
  var value = $(this).val().toLowerCase();
  $container.attr(
    'class', 'row col-12 form-group target-container ' + (value != 'none' ? ' pad '+value : ' pad none'),
  );
} ).change();
// -------------------------------------------------------------------------
$('#padd-char').on('change', '#xk_padding_character', function(e) {
  var $container = $(this).closest('.target-container');
  var value = $(this).val().toLowerCase();
  $container.attr(
    'class', 'col-12 row form-group target-container ' + (value != 'separator' ? ' pch '+value : ' pch none'),
  );
} ).change();
// -------------------------------------------------------------------------
$('#sep').on('change', '#xk_separator_character', function(e) {
  var $container = $(this).closest('.target-container');
  var value = $(this).val().toLowerCase();
  $container.attr(
    'class', 'row col-12 mb-0 form-group target-container ' + (value != 'none' ? ' sep '+value : ' sep none'),
  );
} ).change();

$('#pwd_alg').change();
$('#xk_padding_type').change();
$('#xk_separator_character').change();
$('#xk_padding_character').change();
