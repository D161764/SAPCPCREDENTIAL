const bodyParser = require("body-parser");
const express = require('express');
const fetch = require('node-fetch');
const jose = require('node-jose');
const app = express()
const port = process.env.PORT || 3000
app.use(bodyParser.json())
app.post('/readPassword', async (req, res) => {

    var pvtkey = req.header('private-key');

    var namespace = req.body.namespace;
    var credname = req.body.identifier;
    const authorization = req.header('Authorization');
    var credentialDetails = await getCredential(pvtkey,namespace,credname,authorization);
    res.send(credentialDetails);

    function checkStatus(response) {
        if (!response.ok) throw Error("Unexpected status code: " + response.status);
        return response;
    }


    async function getCredential(pvtkey,namespace,credentialID,authorization){
        const host_url = 'https://credstore.cfapps.eu10.hana.ondemand.com/api/v1/credentials/password?name='+credentialID;
        const result = await fetch(host_url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: authorization,
                'sapcp-credstore-namespace': namespace
            }

        }).then(checkStatus)
            .then(response => response.text())
            .then(payload => decryptPayload(pvtkey, payload))
            .then(JSON.parse);
        return result;
        

    }
    


 

        async function decryptPayload(privateKey, payload) {
            const key = await jose.JWK.asKey(
                `-----BEGIN PRIVATE KEY-----${privateKey}-----END PRIVATE KEY-----`,
                "pem",
                { alg: "RSA-OAEP-256", enc: "A256GCM" }
            );
            const decrypt = await jose.JWE.createDecrypt(key).decrypt(payload);
            const result = decrypt.plaintext.toString();
            return result;
        }

})

app.post('/listOfPasswords', async(req,res)=> {
    var pvtkey = req.header('private-key');

    var namespace = req.body.namespace;
    
    const authorization = req.header('Authorization');
    var credentialDetails = await getCredential(pvtkey, namespace,authorization);
    res.send(credentialDetails);

    function checkStatus(response) {
        if (!response.ok) throw Error("Unexpected status code: " + response.status);
        return response;
    }


    async function getCredential(pvtkey, namespace,authorization) {
        const host_url = 'https://credstore.cfapps.eu10.hana.ondemand.com/api/v1/credentials/passwords';
        const result = await fetch(host_url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                Authorization: authorization,
                'sapcp-credstore-namespace': namespace
            }

        }).then(checkStatus)
            .then(response => response.text())
            .then(payload => decryptPayload(pvtkey, payload))
            .then(JSON.parse);
        return result;


    }





    async function decryptPayload(privateKey, payload) {
        const key = await jose.JWK.asKey(
            `-----BEGIN PRIVATE KEY-----${privateKey}-----END PRIVATE KEY-----`,
            "pem",
            { alg: "RSA-OAEP-256", enc: "A256GCM" }
        );
        const decrypt = await jose.JWE.createDecrypt(key).decrypt(payload);
        const result = decrypt.plaintext.toString();
        return result;
    }
})

app.post('/writePassword',async(req,res)=>{
    var namespace = req.body.namespace;
    var credential = req.body.credential;
    const authorization = req.header('Authorization');
    var pvtkey = req.header('private-key');
    var publickey = req.header('public-key');

    res.send(await writeCredential(publickey, pvtkey, authorization, namespace, credential))

    function checkStatus(response) {
        if (!response.ok) throw Error("Unexpected status code: " + response.status);
        return response;
    }

    async function encryptPayload(publicKey, payload) {
        const key = await jose.JWK.asKey(
            `-----BEGIN PUBLIC KEY-----${publicKey}-----END PUBLIC KEY-----`,
            "pem",
            { alg: "RSA-OAEP-256" }
        );
        const options = {
            contentAlg: "A256GCM",
            compact: true,
            fields: { "iat": Math.round(new Date().getTime() / 1000) }
        };
        const result = await jose.JWE.createEncrypt(options, key).update(Buffer.from(payload, "utf8")).final();
        return result;
    }
    async function decryptPayload(privateKey, payload) {
        const key = await jose.JWK.asKey(
            `-----BEGIN PRIVATE KEY-----${privateKey}-----END PRIVATE KEY-----`,
            "pem",
            { alg: "RSA-OAEP-256", enc: "A256GCM" }
        );
        const decrypt = await jose.JWE.createDecrypt(key).decrypt(payload);
        const result = decrypt.plaintext.toString();
        return result;
    }
    async function fetchAndDecrypt(privateKey, url, method, body,authorization,namespace) {
        const result = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/jose',
                Authorization: authorization,
                'sapcp-credstore-namespace': namespace
            },
            body : body

        })
            .then(checkStatus)
            .then(response => response.text())
            .then(payload => decryptPayload(privateKey, payload))
            .then(JSON.parse);
        return result;
    }

    async function writeCredential(publickey,pvtkey,authorization,namespace,credential) {
        const host_url = 'https://credstore.cfapps.eu10.hana.ondemand.com/api/v1/credentials/password';
        return fetchAndDecrypt(
            pvtkey,
            host_url,
            "post",
            await encryptPayload(publickey, JSON.stringify(credential)),
            authorization,
            namespace
        );
    }

})

app.listen(port, () => {
    console.log('Server is running on port ' + port)
})

