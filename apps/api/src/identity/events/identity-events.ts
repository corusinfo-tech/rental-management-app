/** Central identity outbox taxonomy. Payloads contain identifiers only. */
export const IdentityEventType = {
  VerificationCreated: 'VerificationCreated', VerificationResent: 'VerificationResent', VerificationVerified: 'VerificationVerified', VerificationExpired: 'VerificationExpired', VerificationRevoked: 'VerificationRevoked', VerificationAttemptsExceeded: 'VerificationAttemptsExceeded',
  EmailVerified: 'EmailVerified', SmsVerified: 'SmsVerified', WhatsAppVerified: 'WhatsAppVerified', PasswordResetCompleted: 'PasswordResetCompleted',
} as const;
export type IdentityEventType = (typeof IdentityEventType)[keyof typeof IdentityEventType];
