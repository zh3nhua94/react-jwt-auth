const express = require("express");
const app = express();
var cors = require("cors");
const jwt = require("jsonwebtoken");

const users = require("./data/data");

app.use(express.json());
app.use(cors());

//mock refresh token database
let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
	//take the refresh token from the user
	const refreshToken = req.body.token;

	//send error if there is no token or it's invalid
	if (!refreshToken) return res.status(401).json("You are not authenticated!");
	//if refresh token not inside database
	if (!refreshTokens.includes(refreshToken)) {
		return res.status(403).json("Refresh token is not valid!");
	}
	//if refresh token is valid
	jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
		err && console.log(err);
		//if everything is ok, invalidate this token & create new access token and refresh token, send to user
		refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

		const newAccessToken = generateAccessToken(user);
		const newRefreshToken = generateRefreshToken(user);
		//push to database
		refreshTokens.push(newRefreshToken);

		res.status(200).json({
			accessToken: newAccessToken,
			refreshToken: newRefreshToken,
		});
	});
});

//Generate an access token
const generateAccessToken = (user) => {
	return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
		expiresIn: "5m",
	});
};

//Generate a refresh token
const generateRefreshToken = (user) => {
	return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecretKey");
};

app.post("/api/login", (req, res) => {
	const { username, password } = req.body;
	//Check if user exists
	const user = users.find((u) => {
		return u.username === username && u.password === password;
	});

	if (user) {
		//Generate an access token
		const accessToken = generateAccessToken(user);
		const refreshToken = generateRefreshToken(user);
		//push to database
		refreshTokens.push(refreshToken);
		res.json({
			username: user.username,
			isAdmin: user.isAdmin,
			accessToken,
			refreshToken,
		});
	} else {
		res.status(400).json("Username or password incorrect!");
	}
});

//Verify access token
const verify = (req, res, next) => {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.split(" ")[1];

		//verify token & return (error, decoded_data = user)
		jwt.verify(token, "mySecretKey", (err, user) => {
			if (err) {
				return res.status(403).json("Token is not valid!");
			}
			req.user = user;
			next();
		});
	} else {
		res.status(401).json("You are not authenticated!");
	}
};

//delete a user (only if user is admin or the user himself)
app.delete("/api/users/:userId", verify, (req, res) => {
	if (req.user.id === req.params.userId || req.user.isAdmin) {
		res.status(200).json("User has been deleted.");
	} else {
		res.status(403).json("You are not allowed to delete this user!");
	}
});

//logout and delete refresh token
app.post("/api/logout", verify, (req, res) => {
	const refreshToken = req.body.token;
	//mock database delete the refresh token
	refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
	res.status(200).json("You logged out successfully.");
});

app.listen(8800, () => console.log("Backend server is running!"));
