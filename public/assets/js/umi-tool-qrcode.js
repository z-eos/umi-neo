 $(document).ready(function () {
     var slider = document.getElementById("mod");
     var output = document.getElementById("mod_size");
     output.innerHTML = slider.value;

     slider.oninput = function() {
         output.innerHTML = this.value;
     }
 });
