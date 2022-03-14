var date = new Date();
   var tdate = date.getDate();
   var month = date.getMonth() + 1;
   if(tdate < 10){
       tdate = '0'+ tdate
   }
   if(month < 10){
       month = '0' + month
   }
   var year = date.getUTCFullYear();
   var mindate = year + "-" + month + "-" + tdate
   document.getElementById('mydate1').setAttribute('min',mindate)
   document.getElementById('mydate1').value = mindate