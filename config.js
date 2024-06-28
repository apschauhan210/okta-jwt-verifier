const path = require('path');
const dotenv = require('dotenv').config();
const fs = require('fs');

// Read environment variables from "testenv". Override environment vars if they are already set. https://www.npmjs.com/package/dotenv
// const TESTENV = path.resolve(__dirname, 'testenv');
// if (fs.existsSync(TESTENV)) {
//   const envConfig = dotenv.parse(fs.readFileSync(TESTENV));
//   Object.keys(envConfig).forEach((k) => {
//     process.env[k] = envConfig[k];
//   });
// }

var ISSUER = process.env.ISSUER || 'https://dev-40886562.okta.com/oauth2/default';
var CLIENT_ID = process.env.CLIENT_ID;
var CLIENT_SECRET = process.env.CLIENT_SECRET;
var SPA_CLIENT_ID = process.env.SPA_CLIENT_ID;
var OKTA_TESTING_DISABLEHTTPSCHECK = process.env.OKTA_TESTING_DISABLEHTTPSCHECK ? true : false;

console.log("Client credentials: ", CLIENT_ID, CLIENT_SECRET)

module.exports = {
    webServer: {
        port: 8080,
        oidc: {
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            issuer: ISSUER,
            appBaseUrl: "http://localhost:8080",
            scope: "openid profile email",
            testing: {
                disableHttpsCheck: OKTA_TESTING_DISABLEHTTPSCHECK,
            },
        },
    },
    resourceServer: {
        port: 8000,
        oidc: {
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            issuer: ISSUER,
            testing: {
                disableHttpsCheck: OKTA_TESTING_DISABLEHTTPSCHECK,
            },
        },
        assertClaims: {
            aud: "api://default",
            cid: CLIENT_ID,
        },
    },
};