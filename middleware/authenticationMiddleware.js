function authenticationMiddleware() {
  return function (req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    return res.send(401);
    res.redirect('api/v1');
  };
}

module.exports = authenticationMiddleware;
