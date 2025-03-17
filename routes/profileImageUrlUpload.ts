/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')

const { URL } = require('url');

module.exports = function profileImageUrlUpload () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const requrl = req.body.imageUrl
      if (requrl.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        var myurl = ""
        try {
          //https://stackoverflow.com/questions/30931079/validating-a-url-in-node-js
          myurl = new URL(requrl).toString();
          myurl = myurl.split(';')[0] //dodatkowe zabezpieczenie do CSP
          logger.info(`BAIM: Udana weryifkacja avatar URL: ${req.body.imageUrl} wynik: ${myurl}`)
        } catch (error) {
          myurl = "";
          logger.info(`BAIM: Odrzucenie avatar URL: ${req.body.imageUrl} is not a valid url`);
          next(error)
        }
        const imageRequest = request
          .get(myurl)
          .on('error', function (err: unknown) {
            UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: myurl }) }).catch((error: Error) => { next(error) })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
          })
          .on('response', function (res: Response) {
            if (res.statusCode === 200) {
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(myurl.split('.').slice(-1)[0].toLowerCase()) ? myurl.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
            } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: myurl }) }).catch((error: Error) => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
