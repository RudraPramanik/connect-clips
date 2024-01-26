import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { Response, Request } from 'express';
import { User } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { LoginDto, RegisterDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  // Handles the refreshing of access tokens
  async refreshToken(req: Request, res: Response): Promise<string> {
    const refreshToken = req.cookies('refresh_token');
    if (!refreshToken) {
      throw new UnauthorizedException('refresh token not found');
    }
    let payload;
    try {
      // Verifies the refresh token using JWT service
      payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
      });
    } catch (error) {
      throw new UnauthorizedException('invalid or expired refresh token');
    }

    // Checks if the user associated with the token still exists
    const userExists = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!userExists) {
      throw new BadRequestException('User no longer exists');
    }
    // Generates a new access token, signs it, and sets it as a cookie
    const expiresIn = 15000;
    const expiration = Math.floor(Date.now() / 1000) + expiresIn;
    const accessToken = this.jwtService.sign(
      { ...payload, exp: expiration },
      {
        secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
      },
    );
    res.cookie('access_token', accessToken, { httpOnly: true });
    return accessToken;
  }
  //Private method for issuing access and refresh tokens
  private async issueTokens(user: User, response: Response) {
    const payload = { username: user.fullname, sub: user.id };

    // Generates an access token
    const accessToken = this.jwtService.sign(
      { ...payload },
      {
        secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
        expiresIn: '150sec',
      },
    );

    // Generates a refresh token
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
      expiresIn: '7d',
    });

    // Sets tokens as cookies in the response
    response.cookie('access_token', accessToken, { httpOnly: true });
    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
    });
    return { user };
  }
  //validation based on login credential
  async validateUser(loginDto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: loginDto.email },
    });
    if (user && (await bcrypt.compare(loginDto.password, user.password))) {
      return user;
    }
    return null;
  }
  // Handles the registration of a new user

  async register(registerDto: RegisterDto, response: Response) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: registerDto.email },
    });
    if (existingUser) {
      throw new Error('email already in use');
    }
    // Hashes the password before saving it to the database
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);
    // Creates a new user in the database
    const user = await this.prisma.user.create({
      data: {
        fullname: registerDto.fullname,
        password: hashedPassword,
        email: registerDto.email,
      },
    });
    // Issues tokens (both access and refresh) for the newly registered user
    return this.issueTokens(user, response);
  }

  // Handles the login process
  async login(loginDto: LoginDto, response: Response) {
    // Validates the user based on login credentials
    const user = await this.validateUser(loginDto);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    // Issues tokens (both access and refresh) for the authenticated user
    return this.issueTokens(user, response);
  }

  // Handles the logout process
  async logout(response: Response) {
    // Clears the cookies containing access and refresh tokens
    response.clearCookie('access_token');
    response.clearCookie('refresh_token');
    return 'Successfully logged out';
  }
}
