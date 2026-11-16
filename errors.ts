export type WalletErrorCode =
  | 'INVALID_MNEMONIC' | 'WEAK_PASSWORD' | 'WRONG_PASSWORD_OR_CORRUPT' | 'BAD_VAULT'
  | 'NO_WALLET' | 'WALLET_EXISTS' | 'LOCKED_OUT' | 'SESSION_LOCKED'
  | 'ENTROPY_UNHEALTHY' | 'INVALID_PSBT' | 'UNKNOWN_INPUT' | 'UNEXPECTED_OUTPUT' | 'MISSING_OUTPUT' | 'FEE_TOO_HIGH';

export class WalletError extends Error {
  constructor(
    public readonly code: WalletErrorCode,
    message: string,
    public readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = 'WalletError';
  }
}
