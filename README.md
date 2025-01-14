# simple-web-token

A simple library for creating and verifying web tokens.

## Usage

```typescript
import { AccessToken, RefreshToken, createAccessRefreshPair } from "simple-web-tokens";

app.get("/login", async (req, res) => {
    const userId = createUser(req.body.email, req.body.password);

    const [accessToken, refreshToken] = await createAccessRefreshPair(userId, process.env.PRIVATE_KEY);

    res.json({
        accessToken,
        refreshToken,
    });
});

const authMiddleware = async (req, res, next) => {
    try {
        req.accessToken = await AccessToken.parse(req.headers.authorization, process.env.PRIVATE_KEY);
    } catch (e) {
        return res.status(401).json({ error: "invalid token" });
    }

    if (req.accessToken.expired) {
        try {
            req.refreshToken = await RefreshToken.parse(req.cookies.refreshToken, req.accessToken, process.env.PRIVATE_KEY);
        } catch (e) {
            return res.status(401).json({ error: "invalid token" });
        }

        if (req.refreshToken.expired) return res.status(401).json({ error: "invalid token" });

        const [accessToken, refreshToken] = await createAccessRefreshPair(req.accessToken.userId, process.env.PRIVATE_KEY);

        // 411 is an arbitrary status code to represent new tokens being issued.
        return res.status(411).json({
            accessToken,
            refreshToken,
        });
    }

    req.user = await getUser(req.accessToken.userId);

    return next();
}
```
