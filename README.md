# traefik-lambdaauthorizer
A Traefik plugin that authorizes request and adds authorizer context to requestContext.authorizer.lambda if authorized or returns 401 if not authorized.   Only supports lambda running in local environment.
