function displayModal(element){
  if (element.style.display == 'block' || element.style.display == null)
    {
      element.style.display='none';
    } else {
      element.style.display='block';
    }
}

function alert_user(dastring, dastring2){
 console.log(dastring + "  " + dastring2);
}

function checkPassword(password, password1){
    if(password == password1){
      document.getElementById('password').style.borderColor='green';
    }
    else
    {
        document.getElementById('')
    }
  }