const url = require("url")
const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get("/authorize", (req, res) => {
	var client_id = req.query["client_id"];
	if (client_id in clients) {
		// verify scopes
		var defined_scopes = clients[client_id].scopes
		var request_scopes = req.query.scopes.split(" ")
		if (containsAll(defined_scopes, request_scopes)) {
			var request_id = randomString();
			requests[request_id] = req.query;
			res.render("login", { 'client': clients[client_id], 'scope': req.query.scopes, 'requestId': request_id });
		} else {
			res.send(401);
		}
	} else {
		res.send(401);
	}
})

app.post("/approve", (req, res) => {
	var username = req.body["userName"];
	var password = req.body["password"];
	var request_id = req.body["requestId"]
	if (username in users && password == users[username]) {
		if (request_id in requests) {
			var request = requests[request_id];
			var authCodeKey = randomString();
			authorizationCodes[authCodeKey] = { clientReq: request, userName: username };
			const redirectUri = url.parse(request.redirect_url);
			redirectUri.query = {
				code:authCodeKey,
				state: request.state,
			};
			uri = url.format(redirectUri)
			res.redirect(uri);
		} else {
			 res.send(401);
		}
	} else {
		res.send(401);
	}
})

app.post("/token", (req, res) => {
	if ("authorization" in req.header) {
		var {client_id, client_secret} = decodeAuthCredentials(req.headers.authorization);
		if (clients[client_id].clientSecret == client_secret) {
			var authCodeKey = req.body["code"];
			if (authCodeKey in authorizationCodes) {
				var authCodeKeyValue = authorizationCodes[authCodeKey];
				var tokenObj = {
					userName: authCodeKeyValue.userName,
					scope: authCodeKeyValue.request.scopes
				};
				var jwtToken = jwt.sign(tokenObj, config.privateKey, {algorithm: "RSA256"});
				res.json({
					"access_token": jwtToken,
					"token_type": "Bearer"
				});
			} else {
				return res.send(401);
			}
		} else {
			return res.send(401);
		}
	} else {
		res.send(401);
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
