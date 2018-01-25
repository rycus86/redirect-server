# Simple Redirect Server

*A minimalistic Flask application to redirect incoming URLs.*

## Purpose

This application uses *YAML* configuration to define the HTTP redirects it supports.
It can deal with simple, exact-match rules and also regular expressions with substitutions.

> If you only need these two, better look at a *proper* webserver, like
> [Nginx](https://www.nginx.com/) or [Apache httpd](https://httpd.apache.org/).
 
This project can also provide a simple admin page to add new rules ad-hoc.

