$(document).ready(function () {
    var slider = document.getElementById("bits");
    var output = document.getElementById("bits_size");
    output.innerHTML = slider.value;

    slider.oninput = function() {
	output.innerHTML = this.value;
    }
});
