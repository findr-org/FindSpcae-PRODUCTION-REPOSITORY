#==========================#
#Exceptions.py
#==========================#



class AccountNotFoundError(Exception):
    pass



class AccountInactiveError(Exception):
    pass

class InvalidRefreshTokenError(Exception):
    pass


class SessionNotFoundError(Exception):
    pass

class SessionRevokedError(Exception):
    pass

class SessionExpiredError(Exception):
    pass

class TokenReuseDetectionError(Exception):
    pass