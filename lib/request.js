var crypto = require('crypto');

var Request = exports.Request = function(method, path, query){
  if(typeof path != 'string') throw "Expected string";
  if(typeof query != 'object') throw "Expected object";

  var query_hash = {},
      auth_hash = {},
      k;
  for(key in query){
    k = key.toLowerCase();
    k.substring(0,5) == 'auth_' ? auth_hash[k] = query[key] : query_hash[k] = query[key];
  }

  this.method = method.toUpperCase();
  this.path = path;
  this.query_hash = query_hash;
  this.auth_hash = auth_hash;
};

Request.prototype = {
  sign: function(token){
    this.auth_hash = {
      auth_version: "1.0",
      auth_key: token.key,
      auth_timestamp: new Date().getTime()
    }

    this.auth_hash['auth_signature'] = this.signature(token);

    return this.auth_hash
  },
  authenticate_by_token_with_exceptions: function(token, timestamp_grace){
    timestamp_grace = timestamp_grace || 600;
    this.validate_version();
    this.validate_timestamp(timestamp_grace);
    this.validate_signature(token);
    return true;
  },
  authenticate_by_token: function(token, timestamp_grace){
    timestamp_grace = timestamp_grace || 600;
    try {
      this.authenticate_by_token_with_exceptions(token, timestamp_grace);
      return true;
    } catch(e){
      return false;
    }
  },
  authenticate: function(block, timestamp_grace){
    timestamp_grace = timestamp_grace || 600;
    var key = this.auth_hash['auth_key'];
    if(!key) throw "Authentication key required";

    var token = block(key);
    if(!token || !token.secret){
      throw "Invalid authentication key";
    }
    this.authenticate_by_token_with_exceptions(token, timestamp_grace);
    return token;
  },
  get auth_hash(){
    if(!this._auth_hash || !this._auth_hash['auth_signature']) throw "Request not signed";
    return this._auth_hash;
  },
  set auth_hash(val){
    this._auth_hash = val;
  },
  signature: function(token){
    return crypto.createHmac('sha256', token.secret).update(this.string_to_sign()).digest('hex');
  },
  string_to_sign: function(){
    return [this.method, this.path, this.parameter_string()].join("\n");
  },
  validate_version: function(){
    var version = this.auth_hash['auth_version'];
    if(!version) throw "Version required";
    if(version != '1.0') throw "Version not supported";
    return true;
  },
  validate_timestamp: function(grace){
    if(grace == null) return true;

    var timestamp = this.auth_hash["auth_timestamp"],
        server_time = Math.floor(new Date().getTime()/100),
        error = Math.abs(parseInt(timestamp) - server_time);

    if(!timestamp) throw "Timestamp required";
    if(error >= grace){
      throw "Timestamp expired: Given timestamp "+
        "("+timestamp+") "+
        "not within "+grace+"s of server time "+
        "("+server_time+")";
    }
    return true;
  },
  validate_signature: function(token){
    var _signature = this.signature(token);
    if(this.auth_hash["auth_signature"] != _signature){
      throw "Invalid signature: you should have "+
        "sent "+_signature+
        ", but you sent "+this.auth_hash["auth_signature"];
    }
    return true
  }
};
