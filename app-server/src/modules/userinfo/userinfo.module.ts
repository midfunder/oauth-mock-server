import { Module } from '@nestjs/common';
import { UserInfoService } from './userinfo.service';

@Module({
  providers: [UserInfoService],
  exports: [UserInfoService],
})
export class UserInfo {}
