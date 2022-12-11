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
	let client_id = req.query["client_id"];
	if (!client_id || !(client_id in clients)){
		res.send(401);
		return;
	}
	// verify scopes
	let defined_scopes = clients[client_id].scopes
	let request_scopes = req.query.scope.split(" ")
	if (containsAll(defined_scopes, request_scopes)) {
		let request_id = randomString();
		requests[request_id] = req.query;
		res.render(
			"login",
			{
				'client': clients[client_id],
				'scope': req.query.scope,
				'requestId': request_id,
			});
	} else {
		res.send(401);
	}
})

app.post("/approve", (req, res) => {
	let username = req.body["userName"];
	let password = req.body["password"];
	let request_id = req.body["requestId"];

	if (!(username in users) || !(password == users[username])) {
		res.send(401);
		return;
	}

	if (!(request_id in requests)) {
		res.send(401);
		return;
	}
	let clientRrequest = requests[request_id];
	delete requests[request_id];
	let authCodeKey = randomString();
	authorizationCodes[authCodeKey] =
		{
			clientReq: clientRrequest,
			userName: username
		};
	const redirectUri = url.parse(clientRrequest.redirect_uri);
	redirectUri.query = {
		code: authCodeKey,
		state: clientRrequest.state,
	};
	uri = url.format(redirectUri)
	res.redirect(uri);
})

app.post("/token", (req, res) => {
	let headerAuth = req.headers.authorization;
	if (!headerAuth) {
		res.send(401);
		return;
	}

	let {clientId, clientSecret} = decodeAuthCredentials(headerAuth);
	let client = clients[clientId];
	if (!client || client.clientSecret != clientSecret) {
		res.send(401);
		return;
	}

	let authCodeKey = req.body["code"];
	if (!authCodeKey || !authorizationCodes[authCodeKey]) {
		res.send(401);
		return;
	}

	let authCodeKeyValue = authorizationCodes[authCodeKey];
	delete authorizationCodes[authCodeKey];
	let tokenObj = {
		userName: authCodeKeyValue.userName,
		scope: authCodeKeyValue.clientReq.scope
	};
	let jwtToken = jwt.sign(
		tokenObj,
		config.privateKey,
		{
			algorithm: "RS256",
			expiresIn: 300,
			issuer: "http://localhost:" + config.port,
		});
	res.json({
		"access_token": jwtToken,
		"token_type": "Bearer",
		scope: authCodeKeyValue.clientReq.scope
	});
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
