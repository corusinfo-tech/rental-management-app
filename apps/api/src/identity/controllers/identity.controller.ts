import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Post, Req, UseGuards } from '@nestjs/common';
import { ApiAcceptedResponse, ApiBadRequestResponse, ApiConflictResponse, ApiOkResponse, ApiOperation, ApiTags, ApiTooManyRequestsResponse } from '@nestjs/swagger';
import type { RequestContext } from '../../core/request/request-context';
import { EmailVerificationConfirmDto, EmailVerificationRequestDto, ErrorEnvelopeDto, GenericAcceptedDto, GenericSuccessEnvelopeDto, LoginDto, PasswordResetConfirmDto, PasswordResetRequestDto, RefreshDto, RegisterDto, RegistrationAcceptedDto, RegistrationSuccessEnvelopeDto, SessionDto, SmsVerificationConfirmDto, SmsVerificationRequestDto, TokenPairDto, WhatsAppVerificationConfirmDto, WhatsAppVerificationRequestDto } from '../dto/auth.dto';
import { PublicRegistrationService } from '../registration/public-registration.service';
import { RegistrationThrottleService } from '../registration/registration-throttle.service';
import { EmailVerificationService } from '../verification/email-verification.service';
import { EmailVerificationThrottleService } from '../verification/email-verification-throttle.service';
import { IdentityService } from '../services/identity.service';
import { AccessTokenGuard } from '../authorization/access-token.guard';
import type { IdentityRequest } from '../authorization/request-context';
import { PasswordResetService } from '../password-reset/password-reset.service';
import { SmsVerificationService } from '../sms-verification/sms-verification.service';
import { WhatsAppVerificationService } from '../whatsapp-verification/whatsapp-verification.service';
import { AuthenticationThrottleService } from '../security/authentication-throttle.service';

@ApiTags('Identity')
@Controller({ path: 'auth', version: '1' })
export class IdentityController {
  constructor(
    private readonly registration: PublicRegistrationService,
    private readonly throttle: RegistrationThrottleService,
    private readonly emailVerification: EmailVerificationService,
    private readonly emailVerificationThrottle: EmailVerificationThrottleService,
    private readonly identity: IdentityService,
    private readonly passwordReset: PasswordResetService,
    private readonly smsVerification: SmsVerificationService,
    private readonly whatsappVerification: WhatsAppVerificationService,
    private readonly authenticationThrottle: AuthenticationThrottleService,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Submit a public tenant or landlord registration' })
  @ApiAcceptedResponse({ type: RegistrationSuccessEnvelopeDto, description: 'Consistent accepted response; no session or token is issued.' })
  @ApiBadRequestResponse({ type: ErrorEnvelopeDto, description: 'Validation error.', examples: { validation: { summary: 'Validation error', value: { success: false, error: { statusCode: 400, message: ['firstName must not be empty'] }, meta: { correlationId: '…', requestId: '…' } } } } })
  @ApiConflictResponse({ type: ErrorEnvelopeDto, description: 'Reserved for non-idempotent integrity conflicts; duplicate identities still receive 202.' })
  @ApiTooManyRequestsResponse({ type: ErrorEnvelopeDto, description: 'Registration throttle exceeded.', examples: { throttled: { summary: 'Throttle exceeded', value: { success: false, error: { statusCode: 429, message: 'Too many registration attempts. Please try again later.' }, meta: { correlationId: '…', requestId: '…' } } } } })
  async register(@Body() dto: RegisterDto, @Req() request: RequestContext): Promise<RegistrationAcceptedDto> {
    await this.throttle.enforce(dto, request);
    return this.registration.register(dto);
  }

  @Post('email-verification/request')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Request an email verification through the reusable verification engine without revealing account state' })
  @ApiAcceptedResponse({ type: GenericSuccessEnvelopeDto, description: 'Always returns the same accepted response.' })
  @ApiBadRequestResponse({ type: ErrorEnvelopeDto, description: 'Validation error.' })
  async registerEmailVerificationRequest(@Body() dto: EmailVerificationRequestDto, @Req() request: RequestContext): Promise<GenericAcceptedDto> {
    await this.emailVerificationThrottle.enforce(dto.email, request);
    return this.emailVerification.request(dto.email, request.correlationId);
  }

  @Post('email-verification/confirm')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Confirm an opaque email-verification token through the reusable verification engine' })
  @ApiOkResponse({ type: GenericSuccessEnvelopeDto, description: 'Generic response for valid, invalid, expired, and replayed tokens.' })
  @ApiBadRequestResponse({ type: ErrorEnvelopeDto, description: 'Token format validation error.' })
  confirmEmailVerification(@Body() dto: EmailVerificationConfirmDto, @Req() request: RequestContext): Promise<GenericAcceptedDto> {
    return this.emailVerification.confirm(dto.token, request.correlationId);
  }

  @Post('login') @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Authenticate with email or mobile and password' }) @ApiOkResponse({ type: TokenPairDto, description: 'Generic authentication failure is returned for all rejected credentials.' })
  async login(@Body() dto: LoginDto, @Req() request: RequestContext) { await this.authenticationThrottle.enforce('login', dto.identifier, request); return this.identity.login({ identifier: dto.identifier, password: dto.password, deviceId: request.header('x-device-id') ?? undefined, userAgent: request.header('user-agent') ?? undefined, ipAddress: request.ip }); }

  @Post('refresh') @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Rotate a refresh token and issue a replacement token pair' }) @ApiOkResponse({ type: TokenPairDto })
  async refresh(@Body() dto: RefreshDto, @Req() request: RequestContext) { await this.authenticationThrottle.enforce('refresh', dto.refreshToken, request); return this.identity.refresh(dto.refreshToken); }

  @Post('logout') @UseGuards(AccessTokenGuard) @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Revoke the current session' })
  async logout(@Req() request: IdentityRequest): Promise<GenericAcceptedDto> { await this.identity.logout(request.identity!.sub, request.identity!.sid); return { accepted: true }; }

  @Post('logout-all') @UseGuards(AccessTokenGuard) @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Revoke all sessions for the current user' })
  async logoutAll(@Req() request: IdentityRequest): Promise<GenericAcceptedDto> { await this.identity.logoutAll(request.identity!.sub); return { accepted: true }; }

  @Get('sessions') @UseGuards(AccessTokenGuard) @ApiOperation({ summary: 'List active sessions for the current user' }) @ApiOkResponse({ type: SessionDto, isArray: true })
  sessions(@Req() request: IdentityRequest) { return this.identity.sessions(request.identity!.sub); }

  @Delete('sessions/:sessionId') @UseGuards(AccessTokenGuard) @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Revoke one of the current user’s sessions' })
  async revokeSession(@Param('sessionId') sessionId: string, @Req() request: IdentityRequest): Promise<GenericAcceptedDto> { await this.identity.revokeSession(request.identity!.sub, sessionId); return { accepted: true }; }

  @Post('password-reset/request') @HttpCode(HttpStatus.ACCEPTED) @ApiOperation({ summary: 'Request a password reset without revealing account state' }) @ApiAcceptedResponse({ type: GenericSuccessEnvelopeDto })
  async passwordResetRequest(@Body() dto: PasswordResetRequestDto, @Req() request: RequestContext) { await this.authenticationThrottle.enforce('password-reset', dto.identifier, request); return this.passwordReset.request(dto.identifier, request.correlationId); }

  @Post('password-reset/confirm') @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Confirm a password reset and revoke all sessions' }) @ApiOkResponse({ type: GenericSuccessEnvelopeDto })
  passwordResetConfirm(@Body() dto: PasswordResetConfirmDto, @Req() request: RequestContext) { return this.passwordReset.confirm(dto.token, dto.newPassword, request.correlationId); }

  @Post('sms-verification/request') @HttpCode(HttpStatus.ACCEPTED) @ApiOperation({ summary: 'Request an SMS OTP without revealing account state' }) @ApiAcceptedResponse({ type: GenericSuccessEnvelopeDto })
  async smsVerificationRequest(@Body() dto: SmsVerificationRequestDto, @Req() request: RequestContext) { await this.authenticationThrottle.enforce('sms-verification', dto.mobile, request); return this.smsVerification.request(dto.mobile, request.correlationId); }

  @Post('sms-verification/confirm') @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Confirm an opaque SMS OTP verification token' }) @ApiOkResponse({ type: GenericSuccessEnvelopeDto })
  smsVerificationConfirm(@Body() dto: SmsVerificationConfirmDto, @Req() request: RequestContext) { return this.smsVerification.confirm(dto.token, request.correlationId); }

  @Post('whatsapp-verification/request') @HttpCode(HttpStatus.ACCEPTED) @ApiOperation({ summary: 'Request a WhatsApp OTP without revealing account state' }) @ApiAcceptedResponse({ type: GenericSuccessEnvelopeDto })
  async whatsappVerificationRequest(@Body() dto: WhatsAppVerificationRequestDto, @Req() request: RequestContext) { await this.authenticationThrottle.enforce('whatsapp-verification', dto.mobile, request); return this.whatsappVerification.request(dto.mobile, request.correlationId); }

  @Post('whatsapp-verification/confirm') @HttpCode(HttpStatus.OK) @ApiOperation({ summary: 'Confirm an opaque WhatsApp OTP verification token' }) @ApiOkResponse({ type: GenericSuccessEnvelopeDto })
  whatsappVerificationConfirm(@Body() dto: WhatsAppVerificationConfirmDto, @Req() request: RequestContext) { return this.whatsappVerification.confirm(dto.token, request.correlationId); }
}
