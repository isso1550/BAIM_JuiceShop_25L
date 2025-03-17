/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'fs'
import crypto from 'crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
//const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'
const privateKey = '-----BEGIN PRIVATE KEY-----\r\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDMG/rsR2Hx/5bUQVtbhodBkMt7JBjJNokOPhUB1dq1irSF547znRPkv/Jw65cJD/FYU54X4xDjd09Vug/SQjhNFT0VQ9o0FQlGFurx9R+EQd53YMy3S/odt28gH5ZyAciBiUhyordbRHSeJhywn0+vQz33ls4FjtOsDML2C0WLjBM725wD41eAgARmfui9IK3j/H24c6+xGgHXSe2otpwr5jeZG4e5yRs+tAjgY4QUN65jiKn0b8OFnnDFsbn+9+tUvcrl/ipiLkKkBrs+PmJ/9RElaGTztl4YXZHN+GR8E5kGfC7I5kj60nniMQzskV3v6k5IBHv0D15nJqsZXo0FAgMBAAECggEAB8IuhRRnjYvcygpb9HwwywC72LKeuz32nWh7DZv5RCUBcgTtzaZ/Duxu75+SQ6wWoqK3DosOkB7vuz9R16O1wSmureQWOMbt7dCe3f371Iqub/+UIzQ2Td00UlZxC7oJSvHoI5dk0d7QcgHaiFTd8g25Hsldi8o0k0R+6rGzUze5TPrWixunkJt8SLG9FNcj7+CghtIujeT1wuRkYBjyZk5dilNBiq7WKx8XCM76z38bQFS2ddVPS6JjZ7ROgaPQc/YsWfeVN/LpWDTmNq2E2mmlEqLQGELlb6Hc1YrzIXklUi6SGMG/zeJK7DCbCnrBUTFFIRX+w3XP+Zw8QA7qBwKBgQDxGLJb2jObes48Xh7Sujy93ufHW1e9Bx5TVEdsAlhSWGhtM6yfEDx9VQ0K2KLWVgrJZofe03NRf15cAQT2oEWozgHqurl/wEUaV8ihSqE7Ccckc1KTM6xOh5tXuvavWdTiBhKidggJxjEKIkyo3qBudowS8IS0j6TUeQORYvUPWwKBgQDYufgGVHMnrIZxksccpgVo6zZXxo6TaXJJ3tjcIkR6X3HRPqB4sOjLIf3G38Jcrq8NgCHr+Vw93FsAQeva7N7QtHe2KKMsILlk0CpT4oxmjE7T0LQInjbLOZ6AxJG6tUDge/Y4JOok3g9TyF4BHn1mNIIC/bSmGgIEq+s+83zjHwKBgDOiqnBppyvhfVIIhmlzYZb4qoNT2NKvN5t5LWLAjdH1BUh+DLZ0b8AX+xcblqR5AQ5pWygp+US3Fqp1vW5knQauOFLhcuEdeK9PpbSFm0pdqbzwxfqo0npvKKH9dN/RSXqu+ka5KLePLumQtwJjy9Bcq1tTD9jr+s1WraDxpLKJAoGAMl1VVDM/55JiU/ZmKzQxwaYXpOJRs9QnaR9Oiim0fDO+AYBqTmHeV4Z4sUTCqEM4Dw0d1PbIBuA0jaTEKMYvKZUm1MAw20pnixQNIh1dv18P2o1/qRkLZsLnIMmNjDQe9YwZNgbuGs84BKJlpiDtx1igdg17c7ZLjcZeDu0KssUCgYB7SwD0qyO4/N5++nuskl453Sm6ZEnzSz7BF45ora2U3hS3+sXw7JXI69SG4h8vb2CEGhQEkoVRYh/fwPmef9KthrzdyqhZ7hy1JCqoDiEiMm7FE4tS47yu3aRK4RtthqVFRhbUWB+Ma+iFkfI//dn8U5eLDwutyVylRdj0wiwSBg==\r\n-----END PRIVATE KEY-----'

interface ResponseWithUser {
  status: string
  data: UserModel
  iat: number
  exp: number
  bid: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any)
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any)
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon: string) => {
  if (coupon) {
    const decoded = z85.decode(coupon)
    if (decoded && (hasValidFormat(decoded.toString()) != null)) {
      const parts = decoded.toString().split('-')
      const validity = parts[0]
      if (utils.toMMMYY(new Date()) === validity) {
        const discount = parts[1]
        return parseInt(discount)
      }
    }
  }
  return undefined
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: any) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    console.log("BAIM: Sprawdzanie tokena JWT ", token)
    jwt.verify(token, publicKey, {algorithms: ['RS256']}, (err: Error | null, decoded: any) => { //BAIM
      if (err === null) {
        console.log("BAIM: Token poprawny")
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      } else {
        console.log("BAIM: Token niepoprawny")
        console.warn(err.message)
      }
    })
  }
  next()
}
