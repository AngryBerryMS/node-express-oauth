const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const { timeout } = require("./utils")
const jwt = require("jsonwebtoken")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get("/user-info", (req, res) => {
	if (!("authorization" in req.headers)) {
		res.send(401);
		return;
	}

	let accessToken = req.headers.authorization.slice("bearer ".length);
	let userInfo = null;

	try {
		userInfo = jwt.verify(
			accessToken,
			config.publicKey,
			{algorithms: ["RS256"]});
	}
	catch (e) {
		res.status(401).send("Error: Client unauthorized");
		return;
	}

	if (!userInfo) {
		res.send(401);
		return;
	}

	let user = users[userInfo.userName];
	let userWithRestrictedFields = {};
	let scopesArr = userInfo.scope.split(" ");
	for (let i = 0; i < scopesArr.length; i++) {
		let field = scopesArr[i].slice("permission:".length);
		userWithRestrictedFields[field] = user[field];
	}

	res.json(userWithRestrictedFields);
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
