const bodyParser = require('body-parser')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')
const ExpiryMap = require('expiry-map')

const assertions = require('../assertions')
const samlArtifact = require('../saml-artifact')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)
const NONCE_TIMEOUT = 5 * 60 * 1000
const nonceStore = new ExpiryMap(NONCE_TIMEOUT)

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
        token_endpoint_auth_methods_supported: ['client_secret_post'],
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
      bodyParser.urlencoded({ extended: false }),
      async (req, res) => {
        const { client_id: aud, code: artifact } = req.body
        console.warn(
          `Received artifact ${artifact} from ${aud} and ${req.body.redirect_uri}`,
        )

        const artifactBuffer = Buffer.from(artifact, 'base64')

        let uuid = artifactBuffer.readInt8(artifactBuffer.length - 1)

        // use env NRIC when SHOW_LOGIN_PAGE is false
        if (uuid === -1) {
          uuid =
            idp === 'singPass'
              ? assertions.oidc.singPass.indexOf(assertions.singPassNric)
              : assertions.oidc.corpPass.findIndex(
                  (c) => c.nric === assertions.corpPassNric,
                )
        }

        const nonce = nonceStore.get(encodeURIComponent(artifact))

        const { idTokenClaims, accessToken } = await assertions.oidc.create[
          idp
        ](uuid, `${req.protocol}://${req.get('host')}`, aud, nonce)

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

        const encryptionKey = await jose.JWK.asKey(serviceProvider.cert, 'pem')
        const idToken = await jose.JWE.createEncrypt(
          { format: 'compact', fields: { cty: 'JWT' } },
          encryptionKey,
        )
          .update(signedIdToken)
          .final()

        res.send({
          access_token: accessToken,
          refresh_token: 'refresh',
          scope: 'openid',
          token_type: 'bearer',
          id_token: idToken,
        })
      },
    )

    app.post(
      `/${idp.toLowerCase()}/authorization-info`,
      bodyParser.urlencoded({ extended: false }),
      async (req, res) => {
        const aud = 'foo'

        const { authInfoToken } = await assertions.oidc.authInfo[idp](
          `${req.protocol}://${req.get('host')}`,
          aud,
        )

        res.send(authInfoToken)
      },
    )
  }
  return app
}

module.exports = config
