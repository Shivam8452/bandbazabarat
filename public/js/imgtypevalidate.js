function imageExtensionValidate(i) {
    var validFileExtensions = [".jpg", ".jpeg", ".png"];    
    // var fileInput = document.getElementsById("file-input");
    var fileVal = i.value;
    // alert(i.value);
    if (fileVal.length > 0) {
       var blnValid = false;
        for (var j = 0; j < validFileExtensions.length; j++) {
           var sCurExtension = validFileExtensions[j];
           if (fileVal.substr(fileVal.length - sCurExtension.length, sCurExtension.length).toLowerCase() == sCurExtension.toLowerCase()) {
                      blnValid = true;
                      break;
                  }
              }
               
        if (!blnValid) {
                 alert("Sorry, " + fileVal + " is invalid, allowed extensions are: " + validFileExtensions.join(", "));
                  oInput.value = "";
                  return false;
              }
    }
  }