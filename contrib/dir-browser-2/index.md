This is the README for a directory browsing script for althttpd
originally contributed by forum user "sodface" in [forum post
d63822d97a17e968](/forumpost/d63822d97a17e968).

Brief HOWTO:

- Copy `index` to a directory of your choice and make it executable.
  althttpd will refuse to run it if it is _writeable_ by any user
  other than the owner.
- Browse to the given directory.

Note that:

- The script provides access to all subdirectories under the one in
  which it lives.
- It automatically filters out certain filenames (see the above forum
  post for details).
- The script may require tweaking for any given environment.
