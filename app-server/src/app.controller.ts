import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService, IValue } from './app.service';

import { JwtAuthGuard } from './modules/auth/jwt-auth.guard';
import { JwtContext } from './modules/auth/jwt-context.decorator';
import { UserInfo } from './modules/userinfo/userinfo.service';

@Controller('value')
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @UseGuards(JwtAuthGuard)
  getValue(@JwtContext() authContext: UserInfo): IValue {
    return this.appService.getValue(authContext);
  }
}
