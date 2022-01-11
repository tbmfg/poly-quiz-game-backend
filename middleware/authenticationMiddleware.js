function authenticationMiddleware() {
  return function (req, res, next) {
    console.log(222)
    res.send({ msg: req.isAuthenticated() });
    // if (req.isAuthenticated()) {
    //   return next();
    // }
    // res.redirect('api/v1');
  };
}

module.exports = authenticationMiddleware;
