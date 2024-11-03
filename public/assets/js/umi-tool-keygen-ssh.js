$(document).ready(function () {
    var slider = document.getElementById("bits");
    var output = document.getElementById("bits_size");
    output.innerHTML = slider.value;

    slider.oninput = function() {
	output.innerHTML = this.value;
    }
});

function toggleInputField() {
    const selectElement = document.getElementById('keyType');
    const inputElement = document.getElementById('bitSize');

    if (selectElement.value === "RSA") {
	inputElement.classList.remove('invisible');
    } else {
	inputElement.classList.add('invisible');
    }
}
