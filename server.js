const express = require("express");
const OktaJwtVerifier = require("@okta/jwt-verifier");
var cors = require("cors");

const sampleConfig = require("./config.js");

const oktaJwtVerifier = new OktaJwtVerifier({
    clientId: sampleConfig.resourceServer.oidc.clientId,
    clientSecret: sampleConfig.resourceServer.oidc.clientSecret,
    issuer: sampleConfig.resourceServer.oidc.issuer,
    assertClaims: sampleConfig.resourceServer.assertClaims,
    testing: sampleConfig.resourceServer.oidc.testing,
});

/**
 * A simple middleware that asserts valid access tokens and sends 401 responses
 * if the token is not present or fails validation.  If the token is valid its
 * contents are attached to req.jwt
 */
function authenticationRequired(req, res, next) {
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/Bearer (.+)/);
    console.log("Auth header", authHeader, match);
    if (!match) {
        res.status(401);
        return next("Unauthorized");
    }

    const accessToken = match[1];
    const audience = sampleConfig.resourceServer.assertClaims.aud;
    return oktaJwtVerifier
        .verifyAccessToken(accessToken, audience)
        .then((jwt) => {
            req.jwt = jwt;
            next();
        })
        .catch((err) => {
            res.status(401).send(err.message);
        });
}

function authenticate(req, res, next) {
    process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;
    var request = require("request");

    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/Bearer (.+)/);
    if (!match) {
        res.status(401);
        return next("Unauthorized");
    }

    const accessToken = match[1];

    const axios = require("axios");
    const qs = require("qs");
    let data = qs.stringify({
        token: accessToken,
        token_type_hint: "access_token",
    });

    const authorization = "Basic " + btoa(sampleConfig.resourceServer.oidc.clientId + ":" + sampleConfig.resourceServer.oidc.clientSecret);

    let config = {
        method: "post",
        maxBodyLength: Infinity,
        url: "https://dev-40886562.okta.com/oauth2/default/v1/introspect",
        headers: {
            Accept: "application/json",
            Authorization: authorization,
            "Content-Type": "application/x-www-form-urlencoded",
            Cookie: "JSESSIONID=F2C7BAA47346C9E9021672D230E772C7",
        },
        data: data,
    };

    axios
        .request(config)
        .then((response) => {
            console.log(JSON.stringify(response.data));
            res.json({
                introspection_response: response.data,
                message:
                    "Hello!  There's not much to see here :) Please grab one of our front-end samples for use with this sample resource server",
            });
            next();
        })
        .catch((error) => {
            console.log(error);
            next();
        });

    // var options = {
    //     method: "POST",
    //     url: "https://dev-40886562.okta.com/oauth2/default/v1/introspect",
    //     headers: {
    //         Accept: "application/json",
    //         Authorization:
    //             "Basic MG9haHk4MW1mODQ2S29vOTc1ZDc6b1IteUw3S2J0NFoxYnd0OGYycWxBb3ZidG1OQTNHZVFobEt5cmJvMmRNZjh0S243VVZSdVFvWi0yaEItTUdXTw==",
    //         "Content-Type": "application/x-www-form-urlencoded",
    //         Cookie: "JSESSIONID=802C9AA13685C888B27F31171543153E",
    //     },
    //     form: {
    //         token: accessToken,
    //         token_type_hint: "access_token",
    //     },
    // };
    // request(options, function (error, response) {
    //     if (error) {
    //         res.status(401).send(error);
    //         console.error(error);
    //     }
    //     if (response) {
    //         // res.status(200);
    //         // res.body(response.body);
    //         console.log(response.body);
    //         res.json({
    //             introspection_response: JSON.parse(response.body),
    //             message:
    //                 "Hello!  There's not much to see here :) Please grab one of our front-end samples for use with this sample resource server",
    //         });
    //     }
    //     // next();
    // });
}

const app = express();

/**
 * For local testing only!  Enables CORS for all domains
 */
app.use(cors());

app.get("/", (req, res) => {
    res.json({
        message:
            "Hello!  There's not much to see here :) Please grab one of our front-end samples for use with this sample resource server",
    });
});

/**
 * An example route that requires a valid access token for authentication, it
 * will echo the contents of the access token if the middleware successfully
 * validated the token.
 */
app.get("/secure", authenticate, (req, res) => {
    res.json(req.jwt);
});

/**
 * Another example route that requires a valid access token for authentication, and
 * print some messages for the user if they are authenticated
 */
app.get("/api/messages", authenticationRequired, (req, res) => {
    res.json({
        messages: [
            {
                date: new Date(),
                text: "I am a robot.",
            },
            {
                date: new Date(new Date().getTime() - 1000 * 60 * 60),
                text: "Hello, world!",
            },
        ],
    });
});

app.listen(sampleConfig.resourceServer.port, () => {
    console.log(
        `Resource Server Ready on port ${sampleConfig.resourceServer.port}`
    );
});
