import * as crypto from "crypto";

import { createHash } from "sha256-uint8array";
import { uint8ArrayToHex } from "uint8array-extras";

export function hash(data: string): string {
  const hash = createHash();
  const encoder = new TextEncoder();
  hash.update(encoder.encode(data));
  return uint8ArrayToHex(hash.digest());
}

export function createSignature(data: string, key: string) {
  return hash(data + key);
}

export function createToken(_data: string | {}, key: string) {
  let data: string = "";

  if (typeof _data !== "string") {
    try {
      data = JSON.stringify(_data);
    } catch (e) {
      throw new Error("Data must be a string or JSON-serializable object");
    }
  } else {
    data = _data;
  }

  const signature = createSignature(data, key);
  return btoa(`${btoa(data)}:${signature}`);
}

export function readToken(
  token: string,
): [string | Record<string, any>, string] {
  try {
    let [data, signature] = atob(token).split(":");
    data = atob(data);
    try {
      data = JSON.parse(data);
    } catch (e) {}

    return [data, signature];
  } catch (e) {
    throw new Error("Invalid token");
  }
}

export function verifyToken(token: string, key: string) {
  try {
    let [data, sig] = readToken(token);

    if (typeof data !== "string") data = JSON.stringify(data);
    if (typeof data !== "string") return false;

    const verifiedSig = createSignature(data, key);
    return verifiedSig === sig;
  } catch (e) {
    console.error(e);
    return false;
  }
}

const ONE_SECOND = 1000;
const ONE_MINUTE = 60 * ONE_SECOND;
const FIFTEEN_MINUTES = 15 * ONE_MINUTE;
const ONE_HOUR = 4 * FIFTEEN_MINUTES;
const ONE_DAY = 24 * ONE_HOUR;
const ONE_MONTH = 30 * ONE_DAY;
const ONE_QUARTER = ONE_MONTH * 3;

export class Token {
  token: string;
  expires: number;

  constructor(token: string, expires: number) {
    this.token = token;
    this.expires = expires;
  }

  get expired() {
    return Date.now() > this.expires;
  }
}

export type AccessTokenData = {
  userId: number | string;
  token: string;
  expires: number;
};

export type RefreshTokenData = {
  token: string;
  accessToken: string;
  expires: number;
};

export class AccessToken extends Token {
  userId: number | string;

  constructor(userId: number | string, expires?: number, token?: string) {
    if (!token) token = crypto.randomUUID();
    if (!expires) expires = Date.now() + FIFTEEN_MINUTES;

    super(token, expires);

    this.userId = userId;
  }

  sign(key: string) {
    const data: AccessTokenData = {
      userId: this.userId,
      token: this.token,
      expires: this.expires,
    };

    return createToken(data, key);
  }

  static parse(token: string, key: string) {
    const isValid = verifyToken(token, key);
    if (!isValid) throw new Error("Invalid token");

    const [data, _] = readToken(token) as [AccessTokenData, string];

    return new AccessToken(data.userId, data.expires, data.token);
  }
}

export class RefreshToken extends Token {
  accessToken: AccessToken;

  constructor(accessToken: AccessToken, expires?: number, token?: string) {
    if (!token) token = crypto.randomUUID();
    if (!expires) expires = Date.now() + ONE_QUARTER;

    super(token, expires);

    this.accessToken = accessToken;
  }

  sign(key: string) {
    const data: RefreshTokenData = {
      token: this.token,
      accessToken: this.accessToken.token,
      expires: this.expires,
    };

    return createToken(data, key);
  }

  static parse(token: string, accessToken: AccessToken, key: string) {
    const isValid = verifyToken(token, key);
    if (!isValid) throw new Error("Invalid token");

    const [data, _] = readToken(token) as [RefreshTokenData, string];

    if (data.accessToken !== accessToken.token)
      throw new Error("Invalid token");

    return new RefreshToken(accessToken, data.expires, data.token);
  }
}

export function createAccessRefreshPair(
  userId: number | string,
  key: string,
  accessTokenExpires?: number,
  refreshTokenExpires?: number,
): [string, string] {
  const accessToken = new AccessToken(userId, accessTokenExpires);
  const refreshToken = new RefreshToken(accessToken, refreshTokenExpires);

  return [accessToken.sign(key), refreshToken.sign(key)];
}
