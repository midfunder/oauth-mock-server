import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { Request } from 'express';

import * as LRUCache from 'lru-cache';

export interface UserInfo {
  sub: string;
  email: string;
  name?: string;
  picture?: string;
  email_verified?: boolean;
}

export interface jwtPayload {
  sub: string;
  aud: string[];
}

@Injectable()
export class UserInfoService {
  private cache = new LRUCache<string, UserInfo>({
    max: 1024,
    maxAge: 3600 * 1000, // ms
  });

  async get(request: Request, jwt: jwtPayload): Promise<UserInfo> {
    const uinfo = this.cache.get(jwt.sub);
    const audiences: string[] = jwt.aud;
    if (uinfo !== undefined) {
      return Promise.resolve(uinfo);
    }
    const url = audiences.find((s) => s.endsWith('/userinfo'));
    if (url === undefined) {
      return Promise.reject(new Error('missing userinfo url in aud array'));
    }
    const authorization = request.headers.authorization;
    return axios.get(url, { headers: { authorization } }).then((response) => {
      const userInfo = response.data;
      this.cache.set(jwt.sub, userInfo);
      return userInfo;
    });
  }
}
