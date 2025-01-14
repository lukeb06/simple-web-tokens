import * as crypto from 'crypto';

export async function hash(data: string) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

export async function createSignature(data: string, key: string) {
    return await hash(data + key);
}

export async function createToken(_data: string | {}, key: string) {
    let data: string = '';

    if (typeof _data !== 'string') {
        try {
            data = JSON.stringify(_data);
        } catch (e) {
            throw new Error('data must be a string or JSON-serializable object');
        }
    } else {
        data = _data;
    }

    const signature = await createSignature(data, key);
    return btoa(`${btoa(data)}:${signature}`);
}


export async function readToken(token: string): Promise<[string | {}, string]> {
    try {
        let [data, signature] = atob(token).split(':');
        data = atob(data);
        try {
            data = JSON.parse(data);
        } catch (e) { }

        return [data, signature];
    } catch (e) {
        throw new Error('invalid token');
    }
}

export async function verifyToken(token: string, key: string) {
    try {
        const [data, _] = await readToken(token);
        const verifiedToken = await createToken(data, key);
        return verifiedToken === token;
    } catch (e) {
        console.error(e);
        return false;
    }
}

const ONE_SECOND = 1000;
const ONE_MINUTE = 60 * ONE_SECOND;
const FIFTEEN_MINUTES = 15 * ONE_MINUTE;
const ONE_HOUR = FIFTEEN_MINUTES * 4;
const ONE_DAY = ONE_HOUR * 24;
const ONE_YEAR = ONE_DAY * 365;

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
    userId: number;
    token: string;
    expires: number;
};

export type RefreshTokenData = {
    token: string;
    accessToken: string;
    expires: number;
}

export class AccessToken extends Token {
    userId: number;

    constructor(userId: number, token?: string, expires?: number) {
        if (!token) token = crypto.randomUUID();
        if (!expires) expires = Date.now() + FIFTEEN_MINUTES;

        super(token, expires);

        this.userId = userId;
    }

    async sign(key: string) {
        const data: AccessTokenData = {
            userId: this.userId,
            token: this.token,
            expires: this.expires,
        };

        return await createToken(data, key);
    }

    static async parse(token: string, key: string) {
        const isValid = await verifyToken(token, key)
        if (!isValid) throw new Error('invalid token');

        const [data, _] = await readToken(token) as [AccessTokenData, string];

        return new AccessToken(data.userId, data.token, data.expires);
    }
}

export class RefreshToken extends Token {
    accessToken: AccessToken;

    constructor(accessToken: AccessToken, token?: string, expires?: number) {
        if (!token) token = crypto.randomUUID();
        if (!expires) expires = Date.now() + ONE_YEAR;

        super(token, expires);

        this.accessToken = accessToken;
    }

    async sign(key: string) {
        const data: RefreshTokenData = {
            token: this.token,
            accessToken: this.accessToken.token,
            expires: this.expires,
        };

        return await createToken(data, key);
    }

    static async parse(token: string, accessToken: AccessToken, key: string) {
        const isValid = await verifyToken(token, key)
        if (!isValid) throw new Error('invalid token');

        const [data, _] = await readToken(token) as [RefreshTokenData, string];

        if (data.accessToken !== accessToken.token) throw new Error('invalid token');

        return new RefreshToken(accessToken, data.token, data.expires);
    }
}

export async function createAccessRefreshPair(userId: number, key: string) {
    const accessToken = new AccessToken(userId);
    const refreshToken = new RefreshToken(accessToken);

    return [
        await accessToken.sign(key),
        await refreshToken.sign(key),
    ];
}
