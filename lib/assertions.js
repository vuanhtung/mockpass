const base64 = require('base-64')
const base64url = require('base64url')
const crypto = require('crypto')
const fs = require('fs')
const { render } = require('mustache')
const moment = require('moment')
const jose = require('node-jose')
const path = require('path')

const readFrom = (p) => fs.readFileSync(path.resolve(__dirname, p), 'utf8')

const TEMPLATE = readFrom('../static/saml/unsigned-assertion.xml')
const corpPassTemplate = readFrom('../static/saml/corppass.xml')

const defaultAudience =
  process.env.SERVICE_PROVIDER_ENTITY_ID ||
  'http://sp.example.com/demo1/metadata.php'

const hashAccessToken = (accessToken) => {
  const fullHash = crypto.createHash('sha256')
  fullHash.update(accessToken, 'utf8')
  const fullDigest = fullHash.digest()
  const base64string = fullDigest
    .slice(0, fullDigest.length / 2)
    .toString('base64')
  return base64url.fromBase64(base64string)
}

const myinfo = {
  v2: JSON.parse(readFrom('../static/myinfo/v2.json')),
  v3: JSON.parse(readFrom('../static/myinfo/v3.json')),
}

const saml = {
  singPass: [
    'S8979373D',
    'S8116474F',
    'S8723211E',
    'S5062854Z',
    'T0066846F',
    'F9477325W',
    'S3000024B',
    'S6005040F',
    'S6005041D',
    'S6005042B',
    'S6005043J',
    'S6005044I',
    'S6005045G',
    'S6005046E',
    'S6005047C',
    'S6005064C',
    'S6005065A',
    'S6005066Z',
    'S6005037F',
    'S6005038D',
    'S6005039B',
    'G1612357P',
    'G1612358M',
    'F1612359P',
    'F1612360U',
    'F1612361R',
    'F1612362P',
    'F1612363M',
    'F1612364K',
    'F1612365W',
    'F1612366T',
    'F1612367Q',
    'F1612358R',
    'F1612354N',
    'F1612357U',
    ...Object.keys(myinfo.v2.personas),
  ],
  corpPass: [
    { nric: 'S8979373D', uen: '123456789A' },
    { nric: 'S8116474F', uen: '123456789A' },
    { nric: 'S8723211E', uen: '123456789A' },
    { nric: 'S5062854Z', uen: '123456789B' },
    { nric: 'T0066846F', uen: '123456789B' },
    { nric: 'F9477325W', uen: '123456789B' },
    { nric: 'S3000024B', uen: '123456789C' },
    { nric: 'S6005040F', uen: '123456789C' },
  ],
  create: {
    singPass: (
      nric,
      issuer,
      recipient,
      inResponseTo,
      audience = defaultAudience,
    ) =>
      render(TEMPLATE, {
        attributeName: 'UserName',
        value: nric,
        nric: nric,
        issueInstant: moment.utc().format(),
        recipient,
        issuer,
        inResponseTo,
        audience,
      }),
    corpPass: (
      source,
      issuer,
      recipient,
      inResponseTo,
      audience = defaultAudience,
    ) =>
      render(TEMPLATE, {
        attributeName: source.uen,
        value: base64.encode(render(corpPassTemplate, source)),
        nric: source.nric,
        issueInstant: moment.utc().format(),
        recipient,
        issuer,
        inResponseTo,
        audience,
      }),
  },
}

const oidc = {
  singPass: [
    'S8979373D',
    'S8116474F',
    'S8723211E',
    'S5062854Z',
    'T0066846F',
    'F9477325W',
    'S3000024B',
    'S6005040F',
    'S6005041D',
    'S6005042B',
    'S6005043J',
    'S6005044I',
    'S6005045G',
    'S6005046E',
    'S6005047C',
    'S6005064C',
    'S6005065A',
    'S6005066Z',
    'S6005037F',
    'S6005038D',
    'S6005039B',
    'G1612357P',
    'G1612358M',
    'F1612359P',
    'F1612360U',
    'F1612361R',
    'F1612362P',
    'F1612363M',
    'F1612364K',
    'F1612365W',
    'F1612366T',
    'F1612367Q',
    'F1612358R',
    'F1612354N',
    'F1612357U',
    ...Object.keys(myinfo.v3.personas),
  ],
  corpPass: [
    {
      nric: 'S8979373D',
      name: 'Name of S8979373D',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8116474F',
      name: 'Name of S8116474F',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S8723211E',
      name: 'Name of S8723211E',
      isSingPassHolder: true,
      uen: '123456789A',
    },
    {
      nric: 'S5062854Z',
      name: 'Name of S5062854Z',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'T0066846F',
      name: 'Name of T0066846F',
      isSingPassHolder: true,
      uen: '123456789B',
    },
    {
      nric: 'F9477325W',
      name: 'Name of F9477325W',
      isSingPassHolder: false,
      uen: '123456789B',
    },
    {
      nric: 'S3000024B',
      name: 'Name of S3000024B',
      isSingPassHolder: true,
      uen: '123456789C',
    },
    {
      nric: 'S6005040F',
      name: 'Name of S6005040F',
      isSingPassHolder: true,
      uen: '123456789C',
    },
  ],
  create: {
    singPass: (uuid, iss, aud, nonce) => {
      const nric = oidc.singPass[uuid]
      const sub = `s=${nric},u=${uuid}`

      const accessToken = crypto.randomBytes(15).toString('hex')
      const accessTokenHash = hashAccessToken(accessToken)

      return {
        accessToken,
        idTokenClaims: {
          rt_hash: '',
          at_hash: accessTokenHash,
          iat: Date.now() / 1000,
          exp: Date.now() / 1000 + 24 * 60 * 60,
          iss,
          amr: ['pwd'],
          aud,
          sub,
          ...(nonce ? { nonce } : {}),
        },
      }
    },
    corpPass: async (uuid, iss, aud, nonce) => {
      const baseClaims = {
        iat: Date.now() / 1000,
        exp: Date.now() / 1000 + 24 * 60 * 60,
        iss,
        aud,
      }

      const profile = oidc.corpPass[uuid]
      const sub = `s=${profile.nric},u=${uuid},c=SG`

      const accessTokenClaims = {
        ...baseClaims,
        authorization: {
          EntityInfo: {
            CPEntID: 'R90SS0001A',
            CPEnt_Status: 'Registered',
            CPEnt_TYPE: 'UEN',
            CPNonUEN_RegNo: '',
            CPNonUEN_Country: '',
            CPNonUEN_Name: '',
          },
          AccessInfo: {
            Result_Set: {
              ESrvc_Row_Count: 1,
              ESrvc_Result: [
                {
                  CPESrvcID: 'BGESRV1',
                  Auth_Result_Set: {
                    Row_Count: 2,
                    Row: [
                      {
                        CPEntID_SUB: '',
                        CPRole: '',
                        StartDate: '2016-01-15',
                        EndDate: '2016-02-15',
                      },
                      {
                        CPEntID_SUB: '',
                        CPRole: '',
                        StartDate: '2016-03-15',
                        EndDate: '2017-04-15',
                        Parameter: [
                          {
                            name: 'Year of assessment',
                            value: '2014',
                          },
                          {
                            name: 'other02',
                            value: 'value 02',
                          },
                        ],
                      },
                    ],
                  },
                },
              ],
            },
          },
          TPAccessInfo: {},
        },
      }

      const signingPem = fs.readFileSync(
        path.resolve(__dirname, '../static/certs/spcp-key.pem'),
      )
      const signingKey = await jose.JWK.asKey(signingPem, 'pem')
      const accessToken = await jose.JWS.createSign(
        { format: 'compact' },
        signingKey,
      )
        .update(JSON.stringify(accessTokenClaims))
        .final()

      const accessTokenHash = hashAccessToken(accessToken)

      return {
        accessToken,
        idTokenClaims: {
          ...baseClaims,
          rt_hash: '',
          at_hash: accessTokenHash,
          amr: ['pwd'],
          sub,
          ...(nonce ? { nonce } : {}),
          userInfo: {
            CPAccType: 'User',
            CPUID_FullName: profile.name,
            ISSPHOLDER: profile.isSingPassHolder ? 'YES' : 'NO',
          },
          entityInfo: {
            CPEntID: 'R90SS0001A',
            CPEnt_Status: 'Registered',
            CPEnt_TYPE: 'UEN',
            CPNonUEN_RegNo: '',
            CPNonUEN_Country: '',
            CPNonUEN_Name: '',
          },
        },
      }
    },
  },

  authInfo: {
    corpPass: async (iss, aud) => {
      const baseClaims = {
        iat: Date.now() / 1000,
        exp: Date.now() / 1000 + 24 * 60 * 60,
        iss,
        aud,
      }

      const authInfoClaims = {
        ...baseClaims,
        AuthInfo: {
          Result_Set: {
            ESrvc_Row_Count: 1,
            ESrvc_Result: [
              {
                CPESrvcID: 'SD-CPF2FA',
                Auth_Result_Set: {
                  Row: [
                    {
                      StartDate: '2020-08-28',
                      CPRole: 'CPF2FAR1',
                      Parameter: [
                        {
                          name: 'Date',
                          value: '',
                        },
                        {
                          name: 'Alpha',
                          value: '',
                        },
                        {
                          name: 'Number',
                          value: '',
                        },
                        {
                          name: 'Free Text',
                          value: '',
                        },
                        {
                          name: 'Year',
                          value: '',
                        },
                        {
                          name: 'Alpha',
                          value: '',
                        },
                        {
                          name: 'Number',
                          value: '',
                        },
                        {
                          name: 'Free Text',
                          value: '',
                        },
                      ],
                      CPEntID_SUB: '',
                      EndDate: '9999-12-31',
                    },
                  ],
                  Row_Count: 1,
                },
              },
            ],
          },
        },
        TPAuthInfo: {
          Result_Set: {
            ESrvc_Row_Count: 1,
            ESrvc_Result: [
              {
                Auth_Set: {
                  TP_Auth: [
                    {
                      CP_Clnt_ID: 'VBR000036',
                      CP_ClntEnt_TYPE: 'UEN',
                      Auth_Result_Set: {
                        Row: [
                          {
                            StartDate: '2020-07-29',
                            CPRole: '',
                            CP_ClntEnt_SUB: '',
                            Parameter: [],
                            EndDate: '9999-12-31',
                          },
                        ],
                        Row_Count: 1,
                      },
                    },
                  ],
                  ENT_ROW_COUNT: 1,
                },
                CPESrvcID: 'AGM02',
              },
            ],
          },
        },
      }

      const signingPem = fs.readFileSync(
        path.resolve(__dirname, '../static/certs/spcp-key.pem'),
      )
      const signingKey = await jose.JWK.asKey(signingPem, 'pem')

      const authInfoToken = await jose.JWS.createSign(
        { format: 'compact' },
        signingKey,
      )
        .update(JSON.stringify(authInfoClaims))
        .final()

      return {
        authInfoToken,
      }
    },
  },
}

const singPassNric = process.env.MOCKPASS_NRIC || saml.singPass[0]
const corpPassNric = process.env.MOCKPASS_NRIC || saml.corpPass[0].nric
const uen = process.env.MOCKPASS_UEN || saml.corpPass[0].uen

module.exports = {
  saml,
  oidc,
  myinfo,
  singPassNric,
  corpPassNric,
  uen,
}
