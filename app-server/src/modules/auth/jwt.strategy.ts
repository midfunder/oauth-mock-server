import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { Request } from 'express';
import * as JwksRsa from 'jwks-rsa';

import { UserInfoService, UserInfo } from '../userinfo/userinfo.service';

const handleSigningKeyError = (err, cb) => {
  // If we didn't find a match, can't provide a key.
  if (err && err.name === 'SigningKeyNotFoundError') {
    return cb(null);
  }

  // If an error occured like rate limiting or HTTP issue, we'll bubble up the error.
  if (err) {
    return cb(err);
  }
};

const passportJwtSecret = (options: JwksRsa.ExpressJwtOptions) => {
  if (options === null || options === undefined) {
    throw new JwksRsa.ArgumentError(
      'An options object must be provided when initializing passportJwtSecret'
    );
  }

  if (!options.jwksUri) {
    throw new JwksRsa.ArgumentError(
      'No JWKS provided. Please provide a jwksUri'
    );
  }

  const client = new JwksRsa.JwksClient(options);
  const onError = options.handleSigningKeyError || handleSigningKeyError;

  return function secretProvider(jwt, cb) {
    if (!jwt) {
      return cb(null, null);
    }

    client
      .getSigningKey(jwt.kid)
      .then((key: any) => {
        cb(null, key.publicKey || key.rsaPublicKey);
      })
      .catch((err) => {
        onError(err, (newError) => cb(newError, null));
      });
  };
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private userInfoService: UserInfoService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      algorithms: ['RS256'],
      passReqToCallback: true,
      secretOrKey: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: process.env.AUTH_JWKS_URL,
      }),
    });
  }

  async validate(request: Request, payload: any): Promise<UserInfo> {
    return this.userInfoService.get(request, payload);
  }
}
