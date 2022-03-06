 const fileUploader = document.getElementById('proof');
 const banUploader = document.getElementById('Banner');
 const passUploader = document.getElementById('passbook');
const feedback = document.getElementById('feedback');
const feedbackban = document.getElementById('feedbackban');
const feedbackpass = document.getElementById('feedbackpass');

fileUploader.addEventListener('change', (event) => {
  const file = event.target.files[0];
  console.log('file', file);
  
  const size = file.size;
  console.log('size', size);
  let msg = '';
  
  if (size > 1024 * 1024) {
    msg = `<span style="color:red;">The allowed file size is 1MB.</span>`;
    document.getElementById('proof').value = "";
  } else {
    msg = `<span style="color:green;"> A ${returnFileSize(size)} file has been uploaded successfully. </span>`;
  }
  feedback.innerHTML = msg;
});
banUploader.addEventListener('change', (event) => {
  const file = event.target.files[0];
  console.log('file', file);
  
  const size = file.size;
  console.log('size', size);
  let msg = '';
  
  if (size > 1024 * 1024) {
    msg = `<span style="color:red;">The allowed file size is 1MB.</span>`;
    document.getElementById('Banner').value = "";
  } else {
    msg = `<span style="color:green;"> A ${returnFileSize(size)} file has been uploaded successfully. </span>`;
  }
  feedbackban.innerHTML = msg;
});
passUploader.addEventListener('change', (event) => {
  const file = event.target.files[0];
  console.log('file', file);
  
  const size = file.size;
  console.log('size', size);
  let msg = '';
  
  if (size > 1024 * 1024) {
    msg = `<span style="color:red;">The allowed file size is 1MB.</span>`;
    document.getElementById('passbook').value = "";
  } else {
    msg = `<span style="color:green;"> A ${returnFileSize(size)} file has been uploaded successfully. </span>`;
  }
  feedbackpass.innerHTML = msg;
});

function returnFileSize(number) {
  if(number < 1024) {
    return number + 'bytes';
  } else if(number >= 1024 && number < 1048576) {
    return (number/1024).toFixed(2) + 'KB';
  } else if(number >= 1048576) {
    return (number/1048576).toFixed(2) + 'MB';
  }
}