Signature for Node.js
=====================
Ported line for line from the Ruby gem
[Signature](https://github.com/mloughran/signature)

Usage
-----
Mostly mirrors the [Ruby gem](https://github.com/mloughran/signature)

    var request = new Signature.Request(method, path, params),
        token   = request.authenticate(function(key){
            return new Signature.Token(key, get_creds(key).secret);
        });

Warning
-------
Soooo... yeah. I haven't really tested most of the code. I know I know.
But you'll let me know if anything is amuck, right? Perfect.
