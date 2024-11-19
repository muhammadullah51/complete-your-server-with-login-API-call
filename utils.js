import jwt from 'jsonwebtoken'
import {getUsers} from './database.js'
import fs from 'fs';

// Load the settings from the JSON file
const settings = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
const limiterSettings = settings.default.rateLimiterSettings

const sum = (a, b) => {
    return a + b;
}

// Fixed window rate limiter operations. The rateLimiter is a predicate function, resulting
// true if and only if the number of requests have exceeded for a user in question within the
// time window. Otherwise the result is false. As an side effect, the user record,
// and the http res are being updated. The req is not used herein, but in principle could be used in some case.

const rateLimiter = (user, req, res) => {
    const window = getLimiterWindow()
    // is this user moving to the next window with this request?
    if ( user.rateLimiting.window < window ) {
        user.rateLimiting.window = window;
        user.rateLimiting.requestCounter = 1;
        res.set('X-RateLimit-Remaining', limiterSettings.limit - user.rateLimiting.requestCounter)
    } else { // this window is the same as the previous one for this user    
        if ( user.rateLimiting.requestCounter >= limiterSettings.limit ) { // limit achieved or not?
            res.set('X-RateLimit-Remaining', 0)
            res.status(429).end()   // too many requests =>
            return true             // limited => return true
        } else { // not exceeded, just update the x-ratelimit-remaining accordingly
            user.rateLimiting.requestCounter++;
            res.set('X-RateLimit-Remaining', limiterSettings.limit - user.rateLimiting.requestCounter)
        } 
    }
    return false // not limited, the operations is allowed for this user
}

// Calculate fixed window according to timestamp by dividing it by the windowSizeInMillis config data
// and rounding the result
const getLimiterWindow = () => {
    const window = Math.round( Date.now() / limiterSettings.windowSizeInMillis )
    return window
}

const verifyToken = (req, res, next) => {
    const bearer_token = req.header('Authorization');
    if(bearer_token && bearer_token.toLowerCase().startsWith('bearer ')) {
        const token = bearer_token.substring(7);
        try {
            const decodedToken = jwt.verify(token, 'my_secret_key')
            const now = Date.now() / 1000
            const isValid = (decodedToken.exp - now) >= 0 ? true : false;
            if(isValid) {
                let user = getUsers().find(a => (a.username === decodedToken.username)&&(a.token === token));
                if( user != null ) {
                    if (! rateLimiter( user, req, res ))
                        // rate limit not exceeded, continue to the actual operation:
                        next()
                } else
                    res.status(401).json({"error": "Unauthorized"})
            } else
            res.status(401).json({"error": "Invalid token"})
        } catch (err) {
            res.status(401).json({"error": "Invalid token"})
        }
    } else
        res.status(401).json({"error": "Invalid token"})
} 

export {
    sum,
    verifyToken,
    getLimiterWindow
}