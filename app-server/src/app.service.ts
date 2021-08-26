import { Injectable } from '@nestjs/common';
import { UserInfo } from './modules/userinfo/userinfo.service';

export interface IValue {
  content: string;
}

@Injectable()
export class AppService {
  getValue(userInfo: UserInfo): IValue {
    return {
      content: `Hello ${userInfo.email}!`,
    };
  }
}
