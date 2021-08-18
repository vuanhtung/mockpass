const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')
const jwt_decode = require('jwt-decode')
const ExpiryMap = require('expiry-map')

const assertions = require('../assertions')
const samlArtifact = require('../saml-artifact')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)
const NONCE_TIMEOUT = 5 * 60 * 1000
const nonceStore = new ExpiryMap(NONCE_TIMEOUT)
const ACCESS_TOKEN_TIMEOUT = 24 * 60 * 60 * 1000
const accessTokenStore = new ExpiryMap(ACCESS_TOKEN_TIMEOUT)

const idGenerator = {
  singPass: (rawId) =>
    assertions.myinfo.v3.personas[rawId] ? `${rawId} [MyInfo]` : rawId,
  corpPass: (rawId) => `${rawId.nric} / UEN: ${rawId.uen}`,
}

function config(app, { showLoginPage, idpConfig, serviceProvider }) {
  for (const idp of ['singPass', 'corpPass']) {
    app.get(`/${idp.toLowerCase()}/metadata`, (req, res) => {
      const baseUrl = `${req.protocol}://${req.headers.host}`
      res.send({
        //issuer: req.get('host'),
        issuer: `${baseUrl}`,
        authorization_endpoint: `${baseUrl}/${idp.toLowerCase()}/authorize`,
        token_endpoint: `${baseUrl}/${idp.toLowerCase()}/token`,
        scopes_supported: [
          'openid',
          'profile',
          'email',
          'address',
          'phone',
          'offline_access',
        ],
        response_types_supported: [
          'code',
          'code id_token',
          'id_token',
          'token id_token',
        ],
        claims_supported: ['sub', 'iss', 'acr', 'name'],
        subject_types_supported: ['public', 'pairwise'],
        jwks_uri: `${baseUrl}/${idp.toLowerCase()}/jwks`,
        token_endpoint_auth_methods_supported: [
          'client_secret_post',
          'private_key_jwt',
        ],
      })
    })

    app.get(`/${idp.toLowerCase()}/jwks`, (req, res) => {
      const jwks = fs.readFileSync(
        path.resolve(__dirname, '../../static/certs/jwks.json'),
      )
      res.send(JSON.parse(jwks))
    })

    app.get(`/${idp.toLowerCase()}/spcplogout`, (req, res) => {
      const redirectURI = req.query.return_url
      console.info(`>>> SPCP logout is done, now redirecting to ${redirectURI}`)
      res.redirect(redirectURI)
    })

    app.post(`/${idp.toLowerCase()}/spcplogout`, (req, res) => {
      const redirectURI = req.query.return_url
      console.info(`>>> SPCP logout is done, now redirecting to ${redirectURI}`)
      res.redirect(redirectURI)
    })

    app.get(`/${idp.toLowerCase()}/authorize`, (req, res) => {
      const redirectURI = req.query.redirect_uri
      const state = encodeURIComponent(req.query.state)
      if (showLoginPage) {
        const oidc = assertions.oidc[idp]
        const values = oidc.map((rawId, index) => {
          const code = encodeURIComponent(
            samlArtifact(idpConfig[idp].id, index),
          )
          if (req.query.nonce) {
            nonceStore.set(code, req.query.nonce)
          }
          const assertURL = `${redirectURI}?code=${code}&state=${state}`
          const id = idGenerator[idp](rawId)
          return { id, assertURL }
        })
        const response = render(LOGIN_TEMPLATE, { values })
        res.send(response)
      } else {
        const code = encodeURIComponent(samlArtifact(idpConfig[idp].id))
        if (req.query.nonce) {
          nonceStore.set(code, req.query.nonce)
        }
        const assertURL = `${redirectURI}?code=${code}&state=${state}`
        console.warn(
          `Redirecting login from ${req.query.client_id} to ${redirectURI}`,
        )
        res.redirect(assertURL)
      }
    })

    app.post(
      `/${idp.toLowerCase()}/token`,
      express.urlencoded({ extended: false }),
      async (req, res) => {
        console.log(`Receive token exchange request from ${req.hostname}`)
        console.log(`Request body: ${JSON.stringify(req.body)}`)

        var {
          client_id: aud,
          grant_type: grant,
          client_assertion: clientAuthToken,
        } = req.body
        if (clientAuthToken !== undefined) {
          const clientAuthJwt = jwt_decode(clientAuthToken)
          console.log(`Client auth JWT: ${JSON.stringify(clientAuthJwt)}`)
          aud = clientAuthJwt.sub
        }
        let nonce, uuid

        if (grant === 'refresh_token') {
          const { refresh_token: refreshToken } = req.body
          console.warn(`Refreshing tokens with ${refreshToken}`)

          uuid = refreshToken.split('/')[0]
        } else {
          const { code: artifact } = req.body
          console.warn(
            `Received artifact ${artifact} from ${aud} and ${req.body.redirect_uri}`,
          )
          const artifactBuffer = Buffer.from(artifact, 'base64')
          uuid = artifactBuffer.readInt8(artifactBuffer.length - 1)
          nonce = nonceStore.get(encodeURIComponent(artifact))
        }

        // use env NRIC when SHOW_LOGIN_PAGE is false
        if (uuid === -1) {
          uuid =
            idp === 'singPass'
              ? assertions.oidc.singPass.indexOf(assertions.singPassNric)
              : assertions.oidc.corpPass.findIndex(
                  (c) => c.nric === assertions.corpPassNric,
                )
        }

        const { idTokenClaims, accessToken, refreshToken } =
          await assertions.oidc.create[idp](
            uuid,
            `${req.protocol}://${req.get('host')}`,
            aud,
            nonce,
          )
        accessTokenStore.set(accessToken, 1)

        const signingPem = fs.readFileSync(
          path.resolve(__dirname, '../../static/certs/spcp-key.pem'),
        )
        const signingKey = await jose.JWK.asKey(signingPem, 'pem')
        const signedIdToken = await jose.JWS.createSign(
          { format: 'compact' },
          signingKey,
        )
          .update(JSON.stringify(idTokenClaims))
          .final()

        const encryptionKey = await jose.JWK.asKey(serviceProvider.cert)
        const idToken = await jose.JWE.createEncrypt(
          { format: 'compact', fields: { cty: 'JWT' } },
          encryptionKey,
        )
          .update(signedIdToken)
          .final()

        res.send({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: 24 * 60 * 60,
          scope: 'openid',
          token_type: 'bearer',
          id_token: idToken,
        })
      },
    )

    if (idp.toLowerCase() === 'corppass') {
      app.post(
        `/corppass/authorization-info`,
        express.urlencoded({ extended: false }),
        async (req, res) => {
          console.log(`Receive authz-info request from ${req.hostname}`)
          console.log(`Request body: ${JSON.stringify(req.body)}`)
          console.log(JSON.stringify(req.headers))

          const authzHeader = req.headers['authorization']
          if (authzHeader == null || !authzHeader.startsWith('Bearer')) {
            res.status(403).json({
              error: 'unauthorized',
            })
            return
          }
          const accessToken = authzHeader.substring(7)
          if (!accessTokenStore.has(accessToken)) {
            res.status(403).json({
              error: 'unauthorized',
            })
          }

          const accessTokenJwt = jwt_decode(accessToken)
          const aud = accessTokenJwt.sub
          const { authzInfoJws } = await assertions.authzInfo.create(
            `${req.protocol}://${req.get('host')}`,
            aud,
          )

          res.send(authzInfoJws)
        },
      )
    }
  }
  return app
}

module.exports = config
