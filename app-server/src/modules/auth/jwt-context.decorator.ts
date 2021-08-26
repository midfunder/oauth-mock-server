import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserInfo } from '../userinfo/userinfo.service';

// request 'user' is set by Passport from the return result of the Strategy
// validate method.
export const JwtContext = createParamDecorator<
  string,
  ExecutionContext,
  UserInfo
>((data: string, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.user;
});
