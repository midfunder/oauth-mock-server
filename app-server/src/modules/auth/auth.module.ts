import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UserInfo } from '../userinfo/userinfo.module';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    JwtModule.register({
      verifyOptions: {
        algorithms: ['RS256'],
      },
    }),
    UserInfo,
  ],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}
