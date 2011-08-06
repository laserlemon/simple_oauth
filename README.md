simple_oauth
============
Simply builds and verifies OAuth headers

Continuous Integration
----------------------
[![Build Status](https://secure.travis-ci.org/laserlemon/simple_oauth.png)](http://travis-ci.org/laserlemon/simple_oauth)

Submitting a Pull Request
-------------------------
1. Fork the project.
2. Create a topic branch.
3. Implement your feature or bug fix.
4. Add documentation for your feature or bug fix.
5. Run <tt>bundle exec rake doc:yard</tt>. If your changes are not 100% documented, go back to step 4.
6. Add tests for your feature or bug fix.
7. Run <tt>bundle exec rake test</tt>. If your changes are not 100% covered, go back to step 6.
8. Commit and push your changes.
9. Submit a pull request. Please do not include changes to the gemspec or version file. (If you want to create your own version for some reason, please do so in a separate commit.)

Supported Rubies
----------------
This library aims to support and is [tested
against](http://travis-ci.org/laserlemon/simple_oauth) the following Ruby
implementations:

* Ruby 1.8.7
* Ruby 1.9.1
* Ruby 1.9.2
* Ruby Enterprise Edition 1.8.7

If something doesn't work on one of these interpreters, it should be considered
a bug.

This library may inadvertently work (or seem to work) on other Ruby
implementations, however support will only be provided for the versions listed
above.

If you would like this library to support another Ruby version, you may
volunteer to be a maintainer. Being a maintainer entails making sure all tests
run and pass on that implementation. When something breaks on your
implementation, you will be personally responsible for providing patches in a
timely fashion. If critical issues for a particular implementation exist at the
time of a major release, support for that Ruby version may be dropped.

Copyright
---------
Copyright (c) 2010 Steve Richert, Erik Michaels-Ober.
See [LICENSE](https://github.com/laserlemon/simple_oauth/blob/master/LICENSE.md) for details.
