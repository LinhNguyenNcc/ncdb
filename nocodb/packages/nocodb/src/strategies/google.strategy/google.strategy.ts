import { promisify } from 'util';
import { Injectable, Optional } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import bcrypt from 'bcryptjs';
import type { VerifyCallback } from 'passport-google-oauth20';
import type { FactoryProvider } from '@nestjs/common/interfaces/modules/provider.interface';
import Noco from '~/Noco';
import { UsersService } from '~/services/users/users.service';
import { Plugin, ProjectUser, User } from '~/models';
import { sanitiseUserObj } from '~/utils';
import axios from 'axios';

const GOOGLE_CLIENT_ID =
  '571166262332-gcocjt4evqa72ksm4k11oeuq89bver38.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    @Optional() clientConfig: any,
    private usersService: UsersService,
  ) {
    super(clientConfig);
  }

  async validate(
    req: any,
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    // mostly copied from older code
    const response = await axios.get(`https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${"eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmNzI1NDEwMWY1NmU0MWNmMzVjOTkyNmRlODRhMmQ1NTJiNGM2ZjEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiNTcxMTY2MjYyMzMyLWdjb2NqdDRldnFhNzJrc200azExb2V1cTg5YnZlcjM4LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiNTcxMTY2MjYyMzMyLWdjb2NqdDRldnFhNzJrc200azExb2V1cTg5YnZlcjM4LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEwOTgwNDUwMDgyMTIzMDQ3ODM3IiwiaGQiOiJuY2MuYXNpYSIsImVtYWlsIjoibGluaC5uZ3V5ZW5kdXlAbmNjLmFzaWEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6Ii1FODh1Yy1PZFIxUVBzbjBjbXp5Q0EiLCJuYmYiOjE2OTU4OTIwNzQsIm5hbWUiOiJMaW5oIE5ndXllbiBEdXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSkM2S3UtNUpTZlh0cDRiT2EtRWZqWVdNR0g4MGtXS1IxTWRqbzhvUXpkPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkxpbmgiLCJmYW1pbHlfbmFtZSI6Ik5ndXllbiBEdXkiLCJsb2NhbGUiOiJ2aSIsImlhdCI6MTY5NTg5MjM3NCwiZXhwIjoxNjk1ODk1OTc0LCJqdGkiOiJmN2VkNTA3NGM3NmJjNzAxNTk2ZGJmMTYwZWIzNmE5YTM3YjljNjgxIn0.mqWna-YkPBf48QQ_PQ-6tEDAk1CEHQNBEBb7oYaZ3c8BdPFZcw8m4RLIemKfhLcbE9-h9Ao9J6LOe8xofetRb064hjJdJeMihTYeDfmaQfp6PvX5cnq52dBBqa2_26jLqcKetWe2JwdrsyI0AV_XXeNxd3ctRANfVvLseIGZ3KCgjVI_Uylmpe6-ZUhLRQy3PJeYEjnTtQg_hSdExswWtElx754L3f3szyyO-dEmXftkG8xIdPMkf5jj7a_QeXdp7GkjcIg46K-U9rYWfm6yHZNexBG7wNHL8dDggzBeoBgR4IDqiIq_2IJQ4IXIHcQ2Bw0T4ovK67rCkwnEks3deQ"
  }`);
    const tokenInfo = response.data
    console.log(tokenInfo)
    const email = profile.emails[0].value;
    console.log(email,tokenInfo.email)
    try {
      const user = await User.getByEmail(tokenInfo.email);
      if (user) {
        console.log(user)
        // if project id defined extract project level roles
        if (req.ncProjectId) {
          ProjectUser.get(req.ncProjectId, user.id)
            .then(async (projectUser) => {
              user.roles = projectUser?.roles || user.roles;
              user.roles =
                user.roles === 'owner' ? 'owner,creator' : user.roles;
              // + (user.roles ? `,${user.roles}` : '');

              done(null, sanitiseUserObj(user));
            })
            .catch((e) => done(e));
        } else {
          return done(null, sanitiseUserObj(user));
        }
        // if user not found create new user if allowed
        // or return error
      } else {
        const salt = await promisify(bcrypt.genSalt)(10);
        const user = await this.usersService.registerNewUserIfAllowed({
          email_verification_token: null,
          email: profile.emails[0].value,
          password: '',
          salt,
        });
        return done(null, sanitiseUserObj(user));
      }
    } catch (err) {
      return done(err);
    }
  }

  authorizationParams(options: any) {
    const params = super.authorizationParams(options) as Record<string, any>;

    if (options.state) {
      params.state = options.state;
    }

    return params;
  }

  async authenticate(req: any, options?: any): Promise<void> {
    console.log(req)
    // const googlePlugin = await Plugin.getPluginByTitle('Google');

    // if (googlePlugin && googlePlugin.input) {
    //   const settings = JSON.parse(googlePlugin.input);
    //   process.env.NC_GOOGLE_CLIENT_ID = settings.client_id;
    //   process.env.NC_GOOGLE_CLIENT_SECRET = settings.client_secret;
    // }

    if (
      // !process.env.NC_GOOGLE_CLIENT_ID ||
      // !process.env.NC_GOOGLE_CLIENT_SECRET
      !GOOGLE_CLIENT_ID ||
      !GOOGLE_CLIENT_SECRET
    )
      return this.error({
        message:
          'Google client id or secret not found. Please add it in plugin settings or define env variables.',
      });

    return super.authenticate(req, {
      ...options,
      clientID: GOOGLE_CLIENT_ID ?? '',
      clientSecret: GOOGLE_CLIENT_SECRET ?? '',
      callbackURL: 'http://localhost:3000',
      passReqToCallback: true,
      scope: ['profile', 'email', 'openid'],
      state: req.query.state,
    });
  }
}

export const GoogleStrategyProvider: FactoryProvider = {
  provide: GoogleStrategy,
  inject: [UsersService],
  useFactory: async (usersService: UsersService) => {
    // read client id and secret from env variables
    // if not found provide dummy values to avoid error
    // it will be handled in authenticate method ( reading from plugin )
    const clientConfig = {
      clientID: GOOGLE_CLIENT_ID ?? 'dummy-id',
      clientSecret: GOOGLE_CLIENT_SECRET ?? 'dummy-secret',
      // todo: update url
      callbackURL: 'http://localhost:8080/dahsboard',
      passReqToCallback: true,
      scope: ['profile', 'email', 'openid'],
    };

    return new GoogleStrategy(clientConfig, usersService);
  },
};
