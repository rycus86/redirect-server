# Simple Redirect Server

*A minimalistic Flask application to redirect incoming URLs.*

## Purpose

This application uses *YAML* configuration to define the HTTP redirects it supports.
It can deal with simple, exact-match rules and also regular expressions with substitutions.

> If you only need these two, better look at a *proper* webserver, like
> [Nginx](https://www.nginx.com/) or [Apache httpd](https://httpd.apache.org/).
 
This project can also provide a simple admin page to add new rules ad-hoc.

## Running

To run the application, simply execute:

```shell
$ python app.py
```

To allow connections from anywhere, and to use a custom HTTP port, use:

```shell
$ HTTP_HOST=0.0.0.0 HTTP_PORT=8080 python app.py
```

You also can (and should) override the default secret key for managing sessions,
through the `SECRET_KEY` environment variable, or a key-value pair with the same name
read from the `/var/secrets/flask` file.

You can also run the application as a Docker container:

```shell
$ docker run --rm -it     \
    -e HTTP_HOST=0.0.0.0  \
    -e HTTP_PORT=8080     \
    -p 80:8080            \
    rycus86/redirect-server
```

## Configuration

The application will read rules from *YAML* files found in the `RULES_DIR` directory that
have `yml`, `yaml` or `rules` extension.

A simple configuration, with the admin UI enabled, looks like this:

```yaml
rules:
  - source: /google
    target: https://google.com
    ttl: 30d

  - source: /campaign/(.+)
    target: https://my.site.com/?cmp=\1
    regex: true
    code: 302
  
  - source: /with/headers
    target: https://some.site.com/landing-page
    headers:
      X-Server: redirect-server
      X-Location: landing-page

admin:
  path: /admin-page
  username: admin
  password: admin
```

You can specify the admin password as MD5 or SHA1 hash as well:

```yaml
admin:
  path: /admin
  username: admin
  password:
    md5: 65ed8a5eec59a1a6f75ec845294aead8

admin:
  path: /admin
  username: admin
  password:
    sha1: b37958f21be0b97c823f63ccc45b12368235575f
```

## License

MIT
