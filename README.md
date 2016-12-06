# passgo

A password hashing library for go that uses the steps outlined in [this sophos article](https://nakedsecurity.sophos.com/2013/11/20/serious-security-how-to-store-your-users-passwords-safely/)

[Documentation](https://godoc.org/github.com/chriscasola/passgo)

The basic algorithm:

1. Generate a random 16 byte salt
1. Run the PBKDF2 hashing function using the sha256 hash with 30,000 iterations
1. Take 32 bytes of the hash output
1. Store the iteration count, salt, and final hash output
